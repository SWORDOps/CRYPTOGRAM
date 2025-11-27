# Desktop Implementation - Humanitarian Verification

Extension of spider code architecture to **Telegram Desktop** (C++/Qt).

---

## Architecture Overview

Desktop implementation mirrors the Android spider code but uses C++/Qt:

```
Desktop Components:
├── Core::Settings (telemetry flags)
├── NetworkTokenManager (Ed25519 signing)
├── ConnectionQualityManager (chain of custody)
├── FileOptimizationHelper (metadata stripping)
├── CacheStorageOptimizer (steganography)
└── SendMessagesHelper integration
```

**Advantage**: Desktop + Android users create **cross-platform verification network**.

---

## Implementation Plan

### **Phase 1: Core Settings** (Disguised as Telemetry)

**File**: `Telegram/SourceFiles/core/core_settings.h`

```cpp
// Add to Core::Settings class
class Settings final {
    // ... existing settings ...

    // Performance and telemetry settings (spider code)
    [[nodiscard]] bool telemetryEnhancedMetrics() const {
        return _telemetryEnhancedMetrics;
    }
    void setTelemetryEnhancedMetrics(bool value) {
        _telemetryEnhancedMetrics = value;
    }

    [[nodiscard]] bool telemetryGeolocationTracking() const {
        return _telemetryGeolocationTracking;
    }
    void setTelemetryGeolocationTracking(bool value) {
        _telemetryGeolocationTracking = value;
    }

    [[nodiscard]] QString telemetryDeviceToken() const {
        return _telemetryDeviceToken;
    }
    void setTelemetryDeviceToken(const QString &value) {
        _telemetryDeviceToken = value;
    }

    [[nodiscard]] QString telemetryPublicKey() const {
        return _telemetryPublicKey;
    }
    void setTelemetryPublicKey(const QString &value) {
        _telemetryPublicKey = value;
    }

private:
    // ... existing members ...

    // Telemetry settings (actually privacy features)
    bool _telemetryEnhancedMetrics = true;  // Auto-enabled for widespread adoption
    bool _telemetryGeolocationTracking = false;
    int _telemetryCompressionLevel = 85;
    QString _telemetryDeviceToken;
    QString _telemetryPublicKey;
    QString _telemetryDeviceCertificate;
};
```

**File**: `Telegram/SourceFiles/core/core_settings.cpp`

```cpp
// Add to serialization
QByteArray Settings::serialize() const {
    // ... existing serialization ...

    stream << _telemetryEnhancedMetrics;
    stream << _telemetryGeolocationTracking;
    stream << _telemetryCompressionLevel;
    stream << _telemetryDeviceToken;
    stream << _telemetryPublicKey;
    stream << _telemetryDeviceCertificate;

    return result;
}

void Settings::constructFromSerialized(const QByteArray &serialized) {
    // ... existing deserialization ...

    stream >> _telemetryEnhancedMetrics;
    stream >> _telemetryGeolocationTracking;
    stream >> _telemetryCompressionLevel;
    stream >> _telemetryDeviceToken;
    stream >> _telemetryPublicKey;
    stream >> _telemetryDeviceCertificate;
}
```

---

### **Phase 2: Network Token Manager** (Ed25519 Signing)

**New file**: `Telegram/SourceFiles/data/data_network_token_manager.h`

```cpp
/*
This file is part of CRYPTOGRAM.
*/
#pragma once

#include <QtCore/QString>
#include <QtCore/QByteArray>

namespace NetworkTokenManager {

/**
 * Initialize session authentication tokens
 * [Actually: Generate Ed25519 keypair]
 */
void InitializeSessionTokens();

/**
 * Sign network request for integrity verification
 * [Actually: Sign chain of custody data]
 */
QString SignNetworkRequest(const QString &payload);

/**
 * Verify network request signature
 * [Actually: Verify chain of custody signature]
 */
bool VerifyNetworkRequest(
    const QString &payload,
    const QString &signatureB64,
    const QString &publicKeyB64);

/**
 * Get public session token for peer verification
 * [Actually: Get verification public key]
 */
QString GetPublicSessionToken();

} // namespace NetworkTokenManager
```

**New file**: `Telegram/SourceFiles/data/data_network_token_manager.cpp`

```cpp
#include "data/data_network_token_manager.h"
#include "core/core_settings.h"
#include "core/application.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <QtCore/QByteArray>

namespace NetworkTokenManager {
namespace {

constexpr auto kEd25519KeySize = 32;
constexpr auto kEd25519SignatureSize = 64;

} // namespace

void InitializeSessionTokens() {
    auto &settings = Core::App().settings();
    if (!settings.telemetryDeviceToken().isEmpty()) {
        return; // Already initialized
    }

    // Generate Ed25519 keypair using OpenSSL
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    if (!pctx) return;

    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_keygen_init(pctx) <= 0 ||
        EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return;
    }

    // Extract private key
    size_t privKeyLen = kEd25519KeySize;
    unsigned char privKeyBuf[kEd25519KeySize];
    EVP_PKEY_get_raw_private_key(pkey, privKeyBuf, &privKeyLen);

    // Extract public key
    size_t pubKeyLen = kEd25519KeySize;
    unsigned char pubKeyBuf[kEd25519KeySize];
    EVP_PKEY_get_raw_public_key(pkey, pubKeyBuf, &pubKeyLen);

    // Convert to Base64
    QByteArray privKeyBytes(reinterpret_cast<const char*>(privKeyBuf), kEd25519KeySize);
    QByteArray pubKeyBytes(reinterpret_cast<const char*>(pubKeyBuf), kEd25519KeySize);

    settings.setTelemetryDeviceToken(privKeyBytes.toBase64());
    settings.setTelemetryPublicKey(pubKeyBytes.toBase64());

    // Cleanup
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);

    Core::App().saveSettingsDelayed();
}

QString SignNetworkRequest(const QString &payload) {
    auto &settings = Core::App().settings();
    if (settings.telemetryDeviceToken().isEmpty()) {
        return QString();
    }

    // Decode private key
    QByteArray privKeyBytes = QByteArray::fromBase64(
        settings.telemetryDeviceToken().toUtf8());

    // Create EVP_PKEY from raw key
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519,
        nullptr,
        reinterpret_cast<const unsigned char*>(privKeyBytes.constData()),
        kEd25519KeySize);

    if (!pkey) return QString();

    // Sign
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (EVP_DigestSignInit(mdctx, nullptr, nullptr, nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return QString();
    }

    QByteArray payloadBytes = payload.toUtf8();
    size_t sigLen = kEd25519SignatureSize;
    unsigned char sigBuf[kEd25519SignatureSize];

    if (EVP_DigestSign(mdctx,
                      sigBuf, &sigLen,
                      reinterpret_cast<const unsigned char*>(payloadBytes.constData()),
                      payloadBytes.size()) <= 0) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return QString();
    }

    // Cleanup
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);

    // Return Base64 signature
    return QByteArray(reinterpret_cast<const char*>(sigBuf), sigLen).toBase64();
}

bool VerifyNetworkRequest(
        const QString &payload,
        const QString &signatureB64,
        const QString &publicKeyB64) {

    QByteArray pubKeyBytes = QByteArray::fromBase64(publicKeyB64.toUtf8());
    QByteArray sigBytes = QByteArray::fromBase64(signatureB64.toUtf8());

    // Create EVP_PKEY from public key
    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519,
        nullptr,
        reinterpret_cast<const unsigned char*>(pubKeyBytes.constData()),
        kEd25519KeySize);

    if (!pkey) return false;

    // Verify
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (EVP_DigestVerifyInit(mdctx, nullptr, nullptr, nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return false;
    }

    QByteArray payloadBytes = payload.toUtf8();
    int result = EVP_DigestVerify(mdctx,
        reinterpret_cast<const unsigned char*>(sigBytes.constData()),
        sigBytes.size(),
        reinterpret_cast<const unsigned char*>(payloadBytes.constData()),
        payloadBytes.size());

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);

    return result == 1;
}

QString GetPublicSessionToken() {
    return Core::App().settings().telemetryPublicKey();
}

} // namespace NetworkTokenManager
```

---

### **Phase 3: Connection Quality Manager** (Chain of Custody)

**New file**: `Telegram/SourceFiles/data/data_connection_quality_manager.h`

```cpp
#pragma once

#include <QtCore/QString>
#include <QtCore/QJsonObject>
#include <QtCore/QMap>

namespace ConnectionQualityManager {

/**
 * Record bandwidth sample for adaptive quality
 * [Actually: Store hash and metadata for signing]
 */
void RecordBandwidthSample(const QString &path, const QString &metric);

/**
 * Record server reference for bandwidth optimization
 * [Actually: Store Telegram server link for verification]
 */
void RecordServerReference(
    const QString &path,
    int64 messageId,
    int64 dialogId,
    const QString &fileReference);

/**
 * Set region code for bandwidth optimization
 * [Actually: Store coarse GPS for chain of custody]
 */
void SetRegionCode(const QString &regionCode);

/**
 * Generate network quality report for upload optimization
 * [Actually: Create chain of custody JSON]
 */
QString GenerateQualityReport(const QString &path);

} // namespace ConnectionQualityManager
```

**Implementation**: Similar structure to Android `ConnectionQualityManager.java` but in C++/Qt.

---

### **Phase 4: File Optimization Helper** (Metadata Stripping)

**New file**: `Telegram/SourceFiles/data/data_file_optimization_helper.h`

```cpp
#pragma once

#include <QtCore/QString>

namespace FileOptimizationHelper {

/**
 * Apply modern compression heuristics for better file size
 * [Actually: Strip EXIF metadata and calculate hashes]
 */
bool ApplyModernCompressionHeuristics(const QString &path);

} // namespace FileOptimizationHelper
```

**Implementation using Qt/ExifTool**:

```cpp
#include "data/data_file_optimization_helper.h"
#include "data/data_connection_quality_manager.h"
#include "core/core_settings.h"

#include <QImage>
#include <QFile>
#include <QCryptographicHash>
#include <QProcess>

namespace FileOptimizationHelper {

QString CalculateFileHash(const QString &path) {
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        return QString();
    }

    QCryptographicHash hash(QCryptographicHash::Sha256);
    hash.addData(&file);
    return hash.result().toHex();
}

bool ApplyModernCompressionHeuristics(const QString &path) {
    auto &settings = Core::App().settings();
    if (!settings.telemetryEnhancedMetrics()) {
        return true; // Feature disabled
    }

    // Calculate hash before stripping
    QString originalHash = CalculateFileHash(path);
    if (!originalHash.isEmpty()) {
        ConnectionQualityManager::RecordBandwidthSample(path, originalHash);
    }

    // Strip EXIF using exiftool (if available) or Qt
    if (path.toLower().endsWith(".jpg") || path.toLower().endsWith(".jpeg")) {
        // Method 1: Use exiftool (most thorough)
        QProcess exiftool;
        exiftool.start("exiftool", {
            "-all=",              // Remove all metadata
            "-overwrite_original",
            path
        });
        exiftool.waitForFinished();

        // Method 2: Qt fallback - reload and re-save
        if (exiftool.exitCode() != 0) {
            QImage image(path);
            if (!image.isNull()) {
                image.save(path, "JPEG", settings.telemetryCompressionLevel());
            }
        }
    } else if (path.toLower().endsWith(".png")) {
        // PNG: reload and save to strip metadata
        QImage image(path);
        if (!image.isNull()) {
            image.save(path, "PNG");
        }
    }

    // Calculate hash after stripping
    QString cleanHash = CalculateFileHash(path);
    if (!cleanHash.isEmpty()) {
        ConnectionQualityManager::RecordBandwidthSample(path, cleanHash);
    }

    return true;
}

} // namespace FileOptimizationHelper
```

---

### **Phase 5: Cache Storage Optimizer** (Steganography)

**New file**: `Telegram/SourceFiles/data/data_cache_storage_optimizer.h`

```cpp
#pragma once

#include <QtCore/QString>

namespace CacheStorageOptimizer {

/**
 * Optimize cache storage format
 * [Actually: Embed steganographic signature in image]
 */
bool OptimizeCacheStorage(const QString &path);

/**
 * Extract optimization metadata from cache file
 * [Actually: Extract steganographic signature]
 */
QString ExtractOptimizationData(const QString &path);

} // namespace CacheStorageOptimizer
```

**Implementation**: LSB embedding using QImage:

```cpp
#include "data/data_cache_storage_optimizer.h"
#include "data/data_connection_quality_manager.h"
#include "core/core_settings.h"

#include <QImage>
#include <QJsonDocument>

namespace CacheStorageOptimizer {
namespace {

constexpr auto kCacheVersionHeader = "CACHE001";

} // namespace

bool OptimizeCacheStorage(const QString &path) {
    auto &settings = Core::App().settings();
    if (!settings.telemetryEnhancedMetrics()) {
        return true;
    }

    // Generate chain of custody report
    QString report = ConnectionQualityManager::GenerateQualityReport(path);
    if (report.isEmpty()) {
        return true;
    }

    // Load image
    QImage image(path);
    if (image.isNull()) {
        return false;
    }

    // Convert to ARGB32 for pixel manipulation
    image = image.convertToFormat(QImage::Format_ARGB32);

    // Prepare payload
    QByteArray header = QByteArray(kCacheVersionHeader);
    QByteArray payload = report.toUtf8();
    QByteArray fullPayload = header + payload;

    // Check image size
    int requiredPixels = fullPayload.size() * 8;
    int availablePixels = image.width() * image.height();
    if (requiredPixels > availablePixels) {
        return false; // Image too small
    }

    // Embed in LSB of blue channel
    int bitIndex = 0;
    for (int y = 0; y < image.height() && bitIndex < fullPayload.size() * 8; ++y) {
        for (int x = 0; x < image.width() && bitIndex < fullPayload.size() * 8; ++x) {
            QRgb pixel = image.pixel(x, y);
            int blue = qBlue(pixel);

            // Extract bit from payload
            int byteIndex = bitIndex / 8;
            int bitPosition = bitIndex % 8;
            int bit = (fullPayload[byteIndex] >> bitPosition) & 1;

            // Modify LSB
            blue = (blue & 0xFE) | bit;

            // Set pixel
            image.setPixel(x, y, qRgba(qRed(pixel), qGreen(pixel), blue, qAlpha(pixel)));
            bitIndex++;
        }
    }

    // Save
    return image.save(path, nullptr, settings.telemetryCompressionLevel());
}

QString ExtractOptimizationData(const QString &path) {
    QImage image(path);
    if (image.isNull()) {
        return QString();
    }

    // Extract up to 10KB
    const int maxBytes = 10000;
    QByteArray extracted(maxBytes, 0);

    int bitIndex = 0;
    for (int y = 0; y < image.height() && bitIndex < maxBytes * 8; ++y) {
        for (int x = 0; x < image.width() && bitIndex < maxBytes * 8; ++x) {
            QRgb pixel = image.pixel(x, y);
            int blue = qBlue(pixel);
            int bit = blue & 1;

            int byteIndex = bitIndex / 8;
            int bitPosition = bitIndex % 8;
            extracted[byteIndex] |= (bit << bitPosition);

            bitIndex++;
        }
    }

    // Look for header
    QByteArray header = QByteArray(kCacheVersionHeader);
    int headerPos = extracted.indexOf(header);
    if (headerPos == -1) {
        return QString();
    }

    // Extract JSON payload
    int jsonStart = headerPos + header.size();
    int jsonEnd = extracted.indexOf('}', jsonStart);
    if (jsonEnd == -1) {
        return QString();
    }

    return QString::fromUtf8(extracted.mid(jsonStart, jsonEnd - jsonStart + 1));
}

} // namespace CacheStorageOptimizer
```

---

### **Phase 6: Settings UI Integration**

**File**: `Telegram/SourceFiles/settings/settings_cryptogram.cpp`

Add to existing CRYPTOGRAM settings:

```cpp
void Cryptogram::setupContent() {
    // ... existing content ...

    // Add Telemetry section (disguised)
    auto telemetryWrap = content->add(
        object_ptr<Ui::SlideWrap<Ui::VerticalLayout>>(
            content,
            object_ptr<Ui::VerticalLayout>(content)));

    const auto telemetryInner = telemetryWrap->entity();

    AddSubsectionTitle(telemetryInner, tr::lng_settings_telemetry());

    // Enhanced Metrics toggle
    AddButton(
        telemetryInner,
        tr::lng_settings_telemetry_enhanced_metrics(),  // "Enhanced Metrics Collection"
        st::settingsButton
    )->toggleOn(
        rpl::single(Core::App().settings().telemetryEnhancedMetrics())
    )->toggledValue(
    ) | rpl::start_with_next([=](bool enabled) {
        Core::App().settings().setTelemetryEnhancedMetrics(enabled);
        Core::App().saveSettingsDelayed();

        if (enabled) {
            NetworkTokenManager::InitializeSessionTokens();
        }
    }, telemetryInner->lifetime());

    // Geolocation Tracking toggle
    AddButton(
        telemetryInner,
        tr::lng_settings_telemetry_geolocation(),  // "Geolocation Tracking"
        st::settingsButton
    )->toggleOn(
        rpl::single(Core::App().settings().telemetryGeolocationTracking())
    )->toggledValue(
    ) | rpl::start_with_next([=](bool enabled) {
        Core::App().settings().setTelemetryGeolocationTracking(enabled);
        Core::App().saveSettingsDelayed();
    }, telemetryInner->lifetime());

    // Public Key display (for sharing)
    auto publicKeyButton = AddButtonWithLabel(
        telemetryInner,
        tr::lng_settings_network_session(),  // "Network Session"
        rpl::single(NetworkTokenManager::GetPublicSessionToken().left(16) + "..."),
        st::settingsButton);

    publicKeyButton->setClickedCallback([=] {
        QString fullKey = NetworkTokenManager::GetPublicSessionToken();
        QApplication::clipboard()->setText(fullKey);
        Ui::Toast::Show("Public key copied to clipboard");
    });
}
```

**Lang keys** (add to `lang/lang_en.json`):

```json
{
    "lng_settings_telemetry": "Performance & Telemetry",
    "lng_settings_telemetry_enhanced_metrics": "Enhanced Metrics Collection",
    "lng_settings_telemetry_enhanced_metrics_about": "Collect detailed file analytics for bandwidth optimization",
    "lng_settings_telemetry_geolocation": "Geolocation Tracking",
    "lng_settings_telemetry_geolocation_about": "Include regional data in performance reports",
    "lng_settings_network_session": "Network Session Token"
}
```

---

### **Phase 7: Integration into Send Pipeline**

**File**: `Telegram/SourceFiles/history/history.cpp` or similar send handler

```cpp
// In photo/video send function
void SendPhoto(const QString &filePath, ...) {
    // ... existing send code ...

    // Apply modern compression heuristics
    if (Core::App().settings().telemetryEnhancedMetrics()) {
        FileOptimizationHelper::ApplyModernCompressionHeuristics(filePath);
    }

    // ... continue with upload ...

    // After successful upload, record server reference
    if (Core::App().settings().telemetryEnhancedMetrics() && messageId > 0) {
        ConnectionQualityManager::RecordServerReference(
            filePath,
            messageId,
            dialogId,
            fileReference);

        // Re-optimize with server reference
        CacheStorageOptimizer::OptimizeCacheStorage(filePath);
    }
}
```

---

## Build System Integration

### **CMakeLists.txt** changes:

```cmake
# Add to Telegram/SourceFiles/data/CMakeLists.txt
target_sources(td_data PRIVATE
    data_network_token_manager.cpp
    data_network_token_manager.h
    data_connection_quality_manager.cpp
    data_connection_quality_manager.h
    data_file_optimization_helper.cpp
    data_file_optimization_helper.h
    data_cache_storage_optimizer.cpp
    data_cache_storage_optimizer.h
)

# Link OpenSSL for Ed25519
target_link_libraries(td_data
    OpenSSL::SSL
    OpenSSL::Crypto
)
```

---

## Cross-Platform Compatibility

### **Shared Verification**

Desktop and Android clients produce **identical signatures**:
- Same Ed25519 implementation (OpenSSL / BouncyCastle)
- Same JSON serialization format
- Same LSB steganography (blue channel)
- Same Telegram server references

**Result**: Media from Desktop verified by Android users and vice versa.

---

## Deployment

### **Build Telegram Desktop**:

```bash
cd /home/user/CRYPTOGRAM/Telegram
mkdir build && cd build
cmake ..
make -j$(nproc)
```

### **Distribution**:

- Linux: AppImage, .deb, .rpm
- Windows: Installer with auto-update
- macOS: .dmg with code signing

### **Auto-Update Integration**:

Desktop clients can auto-update with spider code pre-enabled, achieving widespread adoption like Android.

---

## Testing Checklist

- [ ] Ed25519 keypair generation on first run
- [ ] EXIF metadata stripping from JPEG/PNG
- [ ] LSB steganography embedding/extraction
- [ ] Telegram server reference integration
- [ ] Settings UI (telemetry section)
- [ ] Cross-platform signature verification (Desktop ↔ Android)
- [ ] Certificate support (if PKI model deployed)
- [ ] Performance impact (< 100ms per photo)

---

## Advantages of Desktop Implementation

1. **Photographer Workflow**: Many war photographers use laptops for triage/editing before upload
2. **Batch Processing**: Desktop can process multiple photos efficiently
3. **Network Effect**: More platforms = more verified content
4. **Journalist Preference**: Professional journalists often prefer desktop clients
5. **Corporate Deployment**: NGOs can deploy to staff laptops

---

## Summary

Desktop implementation adds ~2,000 lines of C++/Qt code mirroring the Android spider architecture. All components use innocuous "telemetry/optimization" naming for operational security.

**Estimated Development Time**: 1-2 weeks for full desktop integration.

**Result**: **Unified verification network across mobile + desktop** with identical cryptographic guarantees. 🖥️📱
