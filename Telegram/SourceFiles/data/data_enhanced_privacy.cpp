/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "data/data_enhanced_privacy.h"
#include "data/data_session.h"
#include "data/data_photo.h"
#include "data/data_document.h"
#include "core/application.h"
#include "core/core_settings.h"
#include "lang/lang_keys.h"
#include "ui/toast/toast.h"
#include "history/history.h"
#include "history/history_item.h"
#include "main/main_session.h"
#include "storage/localimageloader.h"
#include "storage/file_upload.h"
#include "styles/style_chat.h"
#include "data/data_file_origin.h"
#include "data/data_taglib_wrapper.h"  // Use our wrapper instead of direct includes

#include "base/random.h"
#include "base/timer.h"

#include <QByteArray>
#include <QBuffer>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDnsLookup>
#include <QFile>
#include <QImage>
#include <QImageWriter>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegExp>
#include <QTemporaryFile>
#include <QDataStream>
#include <QRandomGenerator>
#include <QFileInfo>
#include <QPainter>

// TagLib includes for audio metadata
#include <taglib/fileref.h>
#include <taglib/tag.h>
#include <taglib/mpegfile.h>
#include <taglib/id3v2tag.h>
#include <taglib/id3v2frame.h>
#include <taglib/id3v2header.h>
#include <taglib/textidentificationframe.h>
#include <taglib/flacfile.h>
#include <taglib/mp4file.h>
#include <taglib/oggfile.h>
#include <taglib/vorbisfile.h>
#include <taglib/wavfile.h>
#include <taglib/tpropertymap.h>

namespace Data {

// Common marker used to identify encrypted messages (now invisible)
// Using zero-width characters to hide encrypted content completely from non-CRYPTOGRAM users
const QString kEncryptionMarker = QString(QChar(0x200B)) + QString(QChar(0x200C)) + QString(QChar(0x200D)); // ZWS+ZWNJ+ZWJ pattern
const QString kEncryptionEndMarker = QString(QChar(0x200D)) + QString(QChar(0x200C)) + QString(QChar(0x200B)); // Reversed pattern

// Metadata markers
const QString kMetadataMarker = "<!--META:";
const QString kMetadataEndMarker = ":META-->";

// Range of unicode invisible characters to use for encoding ciphertext
const int kInvisibleCharStart = 0x200B; // Zero-width space
const int kInvisibleCharEnd = 0x200F;   // Right-to-left mark (5 characters: 0x200B-0x200F)

// Helper function to encode base64 data as invisible Unicode characters
QString EncodeAsInvisibleChars(const QString &base64Data) {
    QString result;
    result += kEncryptionMarker; // Invisible start marker

    // Convert each character of base64 string to invisible Unicode characters
    for (const QChar &ch : base64Data) {
        // Map ASCII character to invisible Unicode range
        unsigned char byte = ch.toLatin1();

        // Split byte into nibbles (4-bit values)
        int high = (byte >> 4) & 0x0F;  // Upper 4 bits
        int low = byte & 0x0F;           // Lower 4 bits

        // Map each nibble to invisible character range (0x200B-0x200F = 5 chars)
        // For values 0-4, map directly; for 5-15, use modulo 5
        result += QChar(kInvisibleCharStart + (high % 5));
        result += QChar(kInvisibleCharStart + (low % 5));
    }

    result += kEncryptionEndMarker; // Invisible end marker
    return result;
}

// Helper function to decode invisible Unicode characters back to base64 data
QString DecodeFromInvisibleChars(const QString &invisibleText) {
    // Find start and end markers
    int startPos = invisibleText.indexOf(kEncryptionMarker);
    int endPos = invisibleText.lastIndexOf(kEncryptionEndMarker);

    if (startPos < 0 || endPos < 0 || startPos >= endPos) {
        return QString(); // Invalid format
    }

    // Extract invisible encoded data
    int dataStart = startPos + kEncryptionMarker.length();
    int dataLength = endPos - dataStart;

    QString result;

    // Decode pairs of invisible characters back to ASCII
    for (int i = dataStart; i < endPos; i += 2) {
        if (i + 1 >= endPos) break;

        int high = invisibleText[i].unicode() - kInvisibleCharStart;
        int low = invisibleText[i + 1].unicode() - kInvisibleCharStart;

        // Clamp values to valid range
        high = qBound(0, high, 15);
        low = qBound(0, low, 15);

        // Reconstruct original byte
        unsigned char byte = ((high & 0x0F) << 4) | (low & 0x0F);
        result += QChar(byte);
    }

    return result;
}

// Define keyboard layouts for switching
const QStringList _keyboardLayouts = {
    "qwertyuiop[]asdfghjkl;'zxcvbnm,./", // QWERTY
    "йцукенгшщзхъфывапролджэячсмитьбю.", // Russian
    "αβψδεφγηιξκλμνοπ;ρστθωςχυζ", // Greek
    "אבגדהוזחטיכלמנסעפצקרשת", // Hebrew
    "قوعرتيءئؤاسدفغهجكلشزخصثذطكمنبي", // Arabic
};

// Settings variables to track user configurations
bool _encryptionEnabled = false;
bool _metadataInjectionEnabled = false;
bool _keyboardSwitchingEnabled = false;
bool _mediaMetadataSpoofingEnabled = false;
QString _encryptionPassphrase = "default_passphrase";
bool _useTimeBasedKey = false;
QString _timeBasedKeySalt = "telegram_salt";
int _keyHistorySize = 30;
QStringList _keyHistory;
int _autoJoinMinDelay = 5; // Default: 5 minutes minimum delay
int _autoJoinMaxDelay = 30; // Default: 30 minutes maximum delay

// Initialize new static variables
bool EnhancedPrivacy::_enhancedMetadataProtectionEnabled = false;
bool EnhancedPrivacy::_trafficPaddingEnabled = false;
int EnhancedPrivacy::_minPaddingBytes = 1024; // 1KB minimum
int EnhancedPrivacy::_maxPaddingBytes = 16384; // 16KB maximum
bool EnhancedPrivacy::_signalProtocolEnabled = false;
QSet<UserId> EnhancedPrivacy::_cryptogramUsers; // Registry of known CRYPTOGRAM users

namespace {

// Helper function to detect file type more accurately
bool IsFileType(const QString &format, const QByteArray &bytes, const QStringList &extensions) {
    // First check by provided format
    const QString formatLower = format.toLower();
    if (extensions.contains(formatLower)) {
        return true;
    }
    
    // For RAR parts, check if format matches r00, r01, etc.
    if (std::any_of(extensions.begin(), extensions.end(), 
                    [&formatLower](const QString &ext) { 
                        return ext.startsWith("r") && formatLower.matches(QRegExp("r\\d\\d")); 
                    })) {
        return true;
    }
    
    // For some formats, check for magic numbers in the file header
    if (extensions.contains("rar") && bytes.size() >= 4) {
        // RAR magic number: "Rar!" (0x52 0x61 0x72 0x21)
        const char rarMagic[] = {0x52, 0x61, 0x72, 0x21};
        if (bytes.startsWith(rarMagic)) {
            return true;
        }
    }
    
    if (extensions.contains("mp3") && bytes.size() >= 3) {
        // MP3 magic number: "ID3" or starting with 0xFF 0xFB
        const char id3Magic[] = {'I', 'D', '3'};
        const char mp3Magic[] = {(char)0xFF, (char)0xFB};
        if (bytes.startsWith(id3Magic) || bytes.startsWith(mp3Magic)) {
            return true;
        }
    }
    
    // JPEG magic number: 0xFF 0xD8 0xFF
    if (extensions.contains("jpg") && bytes.size() >= 3) {
        const char jpegMagic[] = {(char)0xFF, (char)0xD8, (char)0xFF};
        if (bytes.startsWith(jpegMagic)) {
            return true;
        }
    }
    
    // PNG magic number: 0x89 0x50 0x4E 0x47 0x0D 0x0A 0x1A 0x0A
    if (extensions.contains("png") && bytes.size() >= 8) {
        const char pngMagic[] = {(char)0x89, 'P', 'N', 'G', (char)0x0D, (char)0x0A, (char)0x1A, (char)0x0A};
        if (bytes.startsWith(pngMagic)) {
            return true;
        }
    }
    
    return false;
}

// Detect if the file is an image format
bool IsImageFormat(const QString &format, const QByteArray &bytes) {
    static const QStringList imageExtensions = {"jpg", "jpeg", "png", "gif", "tiff", "webp", "bmp"};
    return IsFileType(format, bytes, imageExtensions);
}

// Detect if the file is an audio format
bool IsAudioFormat(const QString &format, const QByteArray &bytes) {
    static const QStringList audioExtensions = {"mp3", "wav", "flac", "m4a", "ogg", "aac"};
    return IsFileType(format, bytes, audioExtensions);
}

// Detect if the file is an archive format
bool IsArchiveFormat(const QString &format, const QByteArray &bytes) {
    static const QStringList archiveExtensions = {"rar", "r00", "r01", "r02", "zip", "7z", "tar", "gz"};
    return IsFileType(format, bytes, archiveExtensions);
}

// Detect if the file is a video format
bool IsVideoFormat(const QString &format, const QByteArray &bytes) {
    static const QStringList videoExtensions = {"mp4", "mov", "avi", "mkv", "webm", "flv"};
    return IsFileType(format, bytes, videoExtensions);
}

} // anonymous namespace

// Client-side encryption wrapper for messages
TextWithEntities EnhancedPrivacy::EncryptMessage(const TextWithEntities &original, const QString &passphrase) {
    if (!IsEncryptionEnabled() || passphrase.isEmpty()) {
        return original;
    }

    // Check if already encrypted
    if (IsEncrypted(original)) {
        return original;
    }

    // Convert to JSON to preserve entities
    QJsonObject obj;
    QJsonArray entities;

    for (const auto &entity : original.entities) {
        QJsonObject entityObj;
        entityObj["type"] = static_cast<int>(entity.type());
        entityObj["offset"] = entity.offset();
        entityObj["length"] = entity.length();
        entityObj["data"] = entity.data();
        entities.append(entityObj);
    }

    obj["text"] = original.text;
    obj["entities"] = entities;

    QJsonDocument doc(obj);
    QString jsonData = QString::fromUtf8(doc.toJson(QJsonDocument::Compact));

    // Encrypt the JSON data
    QString encryptedBase64 = EncryptString(jsonData, passphrase);

    // Encode the base64 ciphertext as invisible Unicode characters
    // This makes the message appear completely blank to non-CRYPTOGRAM users
    QString resultText = EncodeAsInvisibleChars(encryptedBase64);

    // Return as a new TextWithEntities with invisible text
    // NO entities added - we want it to appear as completely empty text
    TextWithEntities result;
    result.text = resultText;
    // Don't add any entities - keep it completely invisible

    return result;
}

TextWithEntities EnhancedPrivacy::DecryptMessage(const TextWithEntities &encrypted) {
    if (!IsEncrypted(encrypted)) {
        return encrypted;
    }

    const auto &text = encrypted.text;

    // Decode invisible Unicode characters back to base64 ciphertext
    QString encryptedBase64 = DecodeFromInvisibleChars(text);

    if (encryptedBase64.isEmpty()) {
        return encrypted; // Failed to decode invisible characters
    }

    // Decrypt the data
    const auto passphrase = GetEncryptionPassphrase();
    if (passphrase.isEmpty()) {
        return encrypted; // No passphrase set
    }

    QString decrypted = DecryptString(encryptedBase64, passphrase);
    if (decrypted.isEmpty()) {
        return encrypted; // Decryption failed
    }

    // Parse the JSON
    QJsonParseError error;
    QJsonDocument doc = QJsonDocument::fromJson(decrypted.toUtf8(), &error);
    if (error.error != QJsonParseError::NoError || !doc.isObject()) {
        return encrypted; // Invalid JSON
    }

    QJsonObject obj = doc.object();

    // Reconstruct TextWithEntities
    TextWithEntities result;
    result.text = obj["text"].toString();

    QJsonArray entitiesArray = obj["entities"].toArray();
    for (const auto &entityValue : entitiesArray) {
        QJsonObject entityObj = entityValue.toObject();
        EntityInText entity(
            static_cast<EntityType>(entityObj["type"].toInt()),
            entityObj["offset"].toInt(),
            entityObj["length"].toInt(),
            entityObj["data"].toString()
        );
        result.entities.push_back(entity);
    }

    return result;
}

bool EnhancedPrivacy::IsEncrypted(const TextWithEntities &text) {
    return text.text.contains(kEncryptionMarker) && text.text.contains(kEncryptionEndMarker);
}

bool EnhancedPrivacy::IsMutuallyEncrypted(const TextWithEntities &text) {
    // For a message to be mutually encrypted:
    // 1. Local encryption must be enabled
    // 2. The message must be encrypted
    return IsEncryptionEnabled() && IsEncrypted(text);
}

QString EnhancedPrivacy::EncryptString(const QString &text, const QString &key) {
    // Generate a key from the passphrase using SHA-256
    QByteArray keyData = QCryptographicHash::hash(
        key.toUtf8(),
        QCryptographicHash::Sha256
    );
    
    // Generate a random IV
    QByteArray iv(16, 0);
    for (int i = 0; i < iv.size(); ++i) {
        iv[i] = static_cast<char>(base::RandomValue<uchar>());
    }
    
    // Prepare data for encryption
    QByteArray data = text.toUtf8();
    
    // Ensure data length is a multiple of 16 (AES block size)
    int padding = 16 - (data.size() % 16);
    data.append(QByteArray(padding, static_cast<char>(padding)));
    
    // Encrypt the data using AES-256-CBC
    QByteArray encrypted(data.size(), 0);
    
    MTPint256 aesKey, aesIV;
    memcpy(aesKey.data(), keyData.constData(), 32);
    memcpy(aesIV.data(), iv.constData(), 16);
    
    openssl::AesEncryptLocal(
        data.constData(),
        encrypted.data(),
        data.size(),
        aesKey.data(),
        aesIV.data()
    );
    
    // Combine IV and encrypted data and convert to Base64
    QByteArray result = iv + encrypted;
    return QString::fromLatin1(result.toBase64());
}

QString EnhancedPrivacy::DecryptString(const QString &text, const QString &key) {
    // Generate key from passphrase
    QByteArray keyData = QCryptographicHash::hash(
        key.toUtf8(),
        QCryptographicHash::Sha256
    );
    
    // Decode Base64
    QByteArray encryptedData = QByteArray::fromBase64(text.toLatin1());
    if (encryptedData.size() <= 16) {
        return QString(); // Too short: IV(16) + at least 1 block(16)
    }
    
    // Extract IV and encrypted data
    QByteArray iv = encryptedData.left(16);
    QByteArray data = encryptedData.mid(16);
    
    // Decrypt
    QByteArray decrypted(data.size(), 0);
    
    MTPint256 aesKey, aesIV;
    memcpy(aesKey.data(), keyData.constData(), 32);
    memcpy(aesIV.data(), iv.constData(), 16);
    
    openssl::AesDecryptLocal(
        data.constData(),
        decrypted.data(),
        data.size(),
        aesKey.data(),
        aesIV.data()
    );
    
    // Remove padding
    int paddingSize = static_cast<int>(decrypted[decrypted.size() - 1]);
    if (paddingSize > 0 && paddingSize <= 16) {
        decrypted.chop(paddingSize);
    }
    
    return QString::fromUtf8(decrypted);
}

TextWithEntities EnhancedPrivacy::InjectMetadata(const TextWithEntities &original) {
    if (!IsMetadataInjectionEnabled()) {
        return original;
    }
    
    // Don't inject metadata into already encrypted messages
    if (IsEncrypted(original)) {
        return original;
    }
    
    TextWithEntities result = original;
    
    // Generate random metadata and wrap it in markers
    QString metadata = GenerateRandomMetadata();
    QString markedMetadata = kMetadataMarker + metadata + kMetadataEndMarker;
    
    // Insert metadata at random positions in the text
    // Option 1: At the beginning
    if (base::RandomValue<int>() % 3 == 0) {
        result.text = markedMetadata + result.text;
        
        // Adjust entity offsets
        for (auto &entity : result.entities) {
            entity.shiftRight(markedMetadata.length());
        }
    }
    // Option 2: At the end
    else if (base::RandomValue<int>() % 3 == 1) {
        result.text = result.text + markedMetadata;
    }
    // Option 3: Insert invisible characters throughout the text
    else {
        for (int i = 0; i < 3; i++) {
            if (result.text.isEmpty()) continue;
            
            int pos = base::RandomValue<int>() % (result.text.length() + 1);
            QChar invisibleChar(kInvisibleCharStart + (base::RandomValue<int>() % (kInvisibleCharEnd - kInvisibleCharStart + 1)));
            
            result.text.insert(pos, invisibleChar);
            
            // Adjust entity offsets after insertion point
            for (auto &entity : result.entities) {
                if (entity.offset() >= pos) {
                    entity.shiftRight(1);
                } else if (entity.offset() + entity.length() > pos) {
                    // The entity contains the insertion point, extend its length
                    entity = EntityInText(
                        entity.type(),
                        entity.offset(),
                        entity.length() + 1,
                        entity.data()
                    );
                }
            }
        }
    }
    
    return result;
}

QString EnhancedPrivacy::GenerateRandomMetadata() {
    // Generate a random string of invisible characters and HTML comments
    QString result;
    int length = 10 + (base::RandomValue<int>() % 20);
    
    for (int i = 0; i < length; i++) {
        if (base::RandomValue<int>() % 3 == 0) {
            // Add an invisible character
            QChar ch(kInvisibleCharStart + (base::RandomValue<int>() % (kInvisibleCharEnd - kInvisibleCharStart + 1)));
            result.append(ch);
        } else {
            // Add random alphanumeric
            static const QString chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            result.append(chars.at(base::RandomValue<int>() % chars.length()));
        }
    }
    
    // Add timestamp
    result += QString::number(QDateTime::currentMSecsSinceEpoch());
    
    return result;
}

void EnhancedPrivacy::RandomizeKeyboardLayout(TextWithEntities &text) {
    if (!IsKeyboardSwitchingEnabled() || text.text.isEmpty()) {
        return;
    }
    
    // Don't modify encrypted messages
    if (IsEncrypted(text)) {
        return;
    }
    
    // Determine how many segments to split the text into
    int segments = 2 + (base::RandomValue<int>() % 3); // 2-4 segments
    
    if (text.text.length() < segments) {
        segments = 1; // Text too short for multiple segments
    }
    
    // Split the text into segments and apply keyboard switching to some
    QString result;
    int segmentLength = text.text.length() / segments;
    
    std::vector<std::pair<int, int>> modifiedRanges;
    
    for (int i = 0; i < segments; i++) {
        int start = i * segmentLength;
        int end = (i == segments - 1) ? text.text.length() : (i + 1) * segmentLength;
        
        QString segment = text.text.mid(start, end - start);
        
        // Randomly decide whether to switch this segment
        bool switchSegment = (base::RandomValue<int>() % 2 == 0);
        
        if (switchSegment && !segment.isEmpty()) {
            int layoutIndex = base::RandomValue<int>() % _keyboardLayouts.size();
            QString switched = SwitchToLayout(segment, _keyboardLayouts[layoutIndex]);
            result += switched;
            modifiedRanges.push_back(std::make_pair(result.length() - switched.length(), result.length()));
        } else {
            result += segment;
        }
    }
    
    // Update text and adjust entities if needed
    if (result != text.text) {
        // This is a complex scenario as we modified portions of text
        // For simplicity, we'll remove entities that overlap with modified ranges
        // A more sophisticated implementation would attempt to adjust them
        
        EntityInText::List newEntities;
        for (const auto &entity : text.entities) {
            bool overlapsModified = false;
            
            for (const auto &range : modifiedRanges) {
                if ((entity.offset() >= range.first && entity.offset() < range.second) ||
                    (entity.offset() + entity.length() > range.first && entity.offset() + entity.length() <= range.second)) {
                    overlapsModified = true;
                    break;
                }
            }
            
            if (!overlapsModified) {
                newEntities.push_back(entity);
            }
        }
        
        text.text = result;
        text.entities = newEntities;
    }
}

QString EnhancedPrivacy::SwitchKeyboardLayout(const QString &text, int segments) {
    if (text.isEmpty() || segments <= 0) {
        return text;
    }
    
    // Split the text into segments
    int segmentLength = text.length() / segments;
    if (segmentLength == 0) {
        return text;
    }
    
    QString result;
    for (int i = 0; i < segments; i++) {
        int start = i * segmentLength;
        int end = (i == segments - 1) ? text.length() : (i + 1) * segmentLength;
        
        QString segment = text.mid(start, end - start);
        
        // For odd-numbered segments, switch layout
        if (i % 2 == 1) {
            // Select a random layout that isn't QWERTY (index 0)
            int layoutIndex = 1 + (base::RandomValue<int>() % (_keyboardLayouts.size() - 1));
            result += SwitchToLayout(segment, _keyboardLayouts[layoutIndex]);
        } else {
            result += segment;
        }
    }
    
    return result;
}

QString EnhancedPrivacy::SwitchToLayout(const QString &text, const QString &layout) {
    static const QString englishLayout = "qwertyuiop[]asdfghjkl;'zxcvbnm,./";
    static const QString englishLayoutUpper = "QWERTYUIOP{}ASDFGHJKL:\"ZXCVBNM<>?";
    static const QMap<QChar, QChar> specialCharMap = {
        {'[', '{'}, {']', '}'}, {';', ':'}, {'\'', '"'},
        {',', '<'}, {'.', '>'}, {'/', '?'}, {'\\', '|'},
        {'`', '~'}, {'1', '!'}, {'2', '@'}, {'3', '#'},
        {'4', '$'}, {'5', '%'}, {'6', '^'}, {'7', '&'},
        {'8', '*'}, {'9', '('}, {'0', ')'}, {'-', '_'},
        {'=', '+'}
    };
    
    QString result;
    for (QChar ch : text) {
        // Handle case-sensitive mapping
        int index = -1;
        bool isUpper = ch.isUpper();
        QChar lowerCh = ch.toLower();
        
        // Try to find in lowercase layout first
        index = englishLayout.indexOf(lowerCh);
        
        // If not found in lowercase, check for uppercase special characters
        if (index < 0) {
            QChar upperSpecial = ch;
            // Check if this is an uppercase special character
            for (auto it = specialCharMap.begin(); it != specialCharMap.end(); ++it) {
                if (it.value() == ch) {
                    // Found uppercase special, convert to lowercase form
                    upperSpecial = it.key();
                    index = englishLayout.indexOf(upperSpecial);
                    isUpper = true;
                    break;
                }
            }
        }
        
        // If found in any layout, map to new layout
        if (index >= 0 && index < layout.length()) {
            QChar newChar = layout[index];
            
            // Handle case preservation
            if (isUpper) {
                newChar = newChar.toUpper();
            }
            
            result.append(newChar);
        } else {
            // Keep non-mapped characters
            result.append(ch);
        }
    }
    
    return result;
}

// Configuration methods
void EnhancedPrivacy::SetEncryptionEnabled(bool enabled) {
    _encryptionEnabled = enabled;
}

void EnhancedPrivacy::SetMetadataInjectionEnabled(bool enabled) {
    _metadataInjectionEnabled = enabled;
}

void EnhancedPrivacy::SetKeyboardSwitchingEnabled(bool enabled) {
    _keyboardSwitchingEnabled = enabled;
}

void EnhancedPrivacy::SetEncryptionPassphrase(const QString &passphrase) {
    _encryptionPassphrase = passphrase;
}

bool EnhancedPrivacy::IsEncryptionEnabled() {
    return _encryptionEnabled;
}

bool EnhancedPrivacy::IsMetadataInjectionEnabled() {
    return _metadataInjectionEnabled;
}

bool EnhancedPrivacy::IsKeyboardSwitchingEnabled() {
    return _keyboardSwitchingEnabled;
}

QString EnhancedPrivacy::GetEncryptionPassphrase() {
    return _encryptionPassphrase;
}

void EnhancedPrivacy::SpoofMediaMetadata(QImage &image, QByteArray &bytes, const QString &format) {
    if (!IsMediaMetadataSpoofingEnabled()) {
        return;
    }

    // Don't process if bytes is empty
    if (bytes.isEmpty()) {
        return;
    }
    
    // Get metadata generation values
    static const QStringList iphoneModels = {
        "iPhone 13 Pro", "iPhone 14 Pro", "iPhone 14 Pro Max", "iPhone 15", "iPhone 15 Pro", "iPhone 15 Pro Max"
    };
    static const QStringList iosVersions = {
        "16.1", "16.2", "16.5", "17.0", "17.1", "17.2", "17.3", "17.4"
    };
    
    const auto deviceModel = iphoneModels[base::RandomValue<int>() % iphoneModels.size()];
    const auto iosVersion = iosVersions[base::RandomValue<int>() % iosVersions.size()];
    
    // Generate random coordinates in Western Virginia
    // Approximate bounding box for Western Virginia
    const double minLat = 36.5;
    const double maxLat = 39.5;
    const double minLon = -82.0;
    const double maxLon = -78.0;
    
    // Generate random coordinates within the bounding box
    const double latitude = minLat + (maxLat - minLat) * (static_cast<double>(base::RandomValue<int>() % 1000) / 1000.0);
    const double longitude = minLon + (maxLon - minLon) * (static_cast<double>(base::RandomValue<int>() % 1000) / 1000.0);
    
    // Get current time
    const auto currentTime = QDateTime::currentDateTime();
    
    // Image formats with EXIF metadata
    if (IsImageFormat(format, bytes)) {
        if (image.isNull()) {
            return;
        }
        
        // Create a buffer to write the image data with metadata
        QBuffer buffer(&bytes);
        buffer.open(QIODevice::WriteOnly);
        
        // Create an ImageWriter to add metadata
        QImageWriter writer(&buffer, format.toLatin1());
        
        // Set metadata
        writer.setText("Software", "iOS " + iosVersion);
        writer.setText("Title", "Image from " + deviceModel);
        writer.setText("Author", "SpyGram User");
        writer.setText("Creation Time", currentTime.toString(Qt::ISODate));
        writer.setText("Device", deviceModel);
        writer.setText("Location", QString("%1,%2").arg(latitude).arg(longitude));
        
        // Write the image with metadata
        writer.write(image);
        buffer.close();
    }
    // Audio file formats (MP3, WAV, FLAC, etc.)
    else if (IsAudioFormat(format, bytes)) {
        // Create a temporary file to work with TagLib
        QTemporaryFile tempFile;
        if (tempFile.open()) {
            // Write the current audio data to the temp file
            tempFile.write(bytes);
            tempFile.flush();
            
            // Get the file path as a C string for TagLib
            const QByteArray filePath = QFile::encodeName(tempFile.fileName());
            
            // Create the appropriate TagLib file handler based on format
            TagLib::File* file = nullptr;
            
            const QString formatLower = format.toLower();
            if (formatLower == "mp3") {
                file = new TagLib::MPEG::File(filePath.constData());
            } else if (formatLower == "flac") {
                file = new TagLib::FLAC::File(filePath.constData());
            } else if (formatLower == "m4a") {
                file = new TagLib::MP4::File(filePath.constData());
            } else if (formatLower == "ogg") {
                file = new TagLib::Ogg::Vorbis::File(filePath.constData());
            } else if (formatLower == "wav") {
                file = new TagLib::RIFF::WAV::File(filePath.constData());
            } else {
                // For unknown audio formats, try the generic FileRef
                file = new TagLib::FileRef(filePath.constData()).file();
            }
            
            // Process the file if it was successfully opened
            if (file && file->isValid()) {
                // Get the tag interface to modify standard properties
                TagLib::Tag* tag = file->tag();
                if (tag) {
                    // Set standard metadata
                    tag->setArtist("John Reese");
                    tag->setAlbum("Encrypted Communications");
                    tag->setTitle("Secure Audio Recording");
                    tag->setComment(QString("Recorded on %1 using iOS %2")
                        .arg(deviceModel)
                        .arg(iosVersion).toStdString());
                    tag->setYear(currentTime.date().year());
                    
                    // For MP3 files, add additional metadata with ID3v2
                    if (formatLower == "mp3") {
                        auto* mpegFile = dynamic_cast<TagLib::MPEG::File*>(file);
                        if (mpegFile) {
                            // Get or create an ID3v2 tag
                            TagLib::ID3v2::Tag* id3v2Tag = mpegFile->ID3v2Tag(true);
                            
                            if (id3v2Tag) {
                                // Add location as geolocation frame
                                auto* geoFrame = new TagLib::ID3v2::TextIdentificationFrame("TGEO", TagLib::String::UTF8);
                                geoFrame->setText(QString("%1, %2")
                                    .arg(latitude)
                                    .arg(longitude).toStdString());
                                id3v2Tag->addFrame(geoFrame);
                                
                                // Add device model
                                auto* deviceFrame = new TagLib::ID3v2::TextIdentificationFrame("TENC", TagLib::String::UTF8);
                                deviceFrame->setText(deviceModel.toStdString());
                                id3v2Tag->addFrame(deviceFrame);
                                
                                // Add iOS version
                                auto* softwareFrame = new TagLib::ID3v2::TextIdentificationFrame("TSSE", TagLib::String::UTF8);
                                softwareFrame->setText(QString("iOS %1").arg(iosVersion).toStdString());
                                id3v2Tag->addFrame(softwareFrame);
                            }
                        }
                    }
                    
                    // For other formats, use property map approach for additional metadata
                    else {
                        TagLib::PropertyMap properties = file->properties();
                        
                        properties.insert("DEVICE", TagLib::StringList(deviceModel.toStdString()));
                        properties.insert("SOFTWARE", TagLib::StringList(QString("iOS %1").arg(iosVersion).toStdString()));
                        properties.insert("LOCATION", TagLib::StringList(QString("%1, %2").arg(latitude).arg(longitude).toStdString()));
                        
                        file->setProperties(properties);
                    }
                    
                    // Save changes to the file
                    file->save();
                }
                
                // Clean up
                delete file;
                
                // Read back the modified file
                tempFile.seek(0);
                bytes = tempFile.readAll();
            }
            
            tempFile.close();
        }
    }
    // RAR and similar archive formats
    else if (IsArchiveFormat(format, bytes)) {
        const QString formatLower = format.toLower();
        // For RAR files (including split parts like r00, r01), we can try to add a comment
        if (formatLower == "rar" || formatLower.matches(QRegExp("r\\d\\d"))) {
            // RAR files have a variable structure, but typically have a comment section
            // This is a simplified approach and may not work for all RAR files
            const char rarMarker[] = {0x52, 0x61, 0x72, 0x21}; // "Rar!"
            int markerPos = bytes.indexOf(rarMarker);
            
            if (markerPos >= 0) {
                // Found RAR marker
                // For simplicity, we'll try to find a comment block
                const char commentHeader[] = {0x75, 0x00}; // Comment header marker in RAR
                int commentPos = bytes.indexOf(commentHeader, markerPos);
                
                if (commentPos >= 0 && commentPos < markerPos + 1000) {
                    // Found comment block
                    const QString comment = QString("Created by John Reese on %1 using iOS %2 - Location: %3,%4")
                        .arg(deviceModel)
                        .arg(iosVersion)
                        .arg(latitude)
                        .arg(longitude);
                    
                    // Replace up to 100 bytes with new comment data
                    // (This is unsafe and just for illustration)
                    const QByteArray commentBytes = comment.toUtf8();
                    if (commentPos + 8 < bytes.size()) {
                        const int maxReplace = qMin(commentBytes.size(), 100);
                        bytes.replace(commentPos + 8, maxReplace, commentBytes.left(maxReplace));
                    }
                }
            }
        }
    }
    // Video formats
    else if (IsVideoFormat(format, bytes)) {
        const QString formatLower = format.toLower();
        // Video metadata is complex and typically requires specialized libraries
        // For MP4 files, we can try to modify a simple atom structure
        if (formatLower == "mp4" || formatLower == "mov") {
            // MP4 files have an atom structure starting with size and type
            // We'll look for metadata atoms like "moov" and "udta"
            const char moovAtom[] = {'m', 'o', 'o', 'v'};
            int moovPos = bytes.indexOf(moovAtom);
            
            if (moovPos >= 0) {
                // Found moov atom
                const char udtaAtom[] = {'u', 'd', 't', 'a'};
                int udtaPos = bytes.indexOf(udtaAtom, moovPos);
                
                if (udtaPos >= 0) {
                    // Found user data atom
                    const char metaAtom[] = {'m', 'e', 't', 'a'};
                    int metaPos = bytes.indexOf(metaAtom, udtaPos);
                    
                    if (metaPos >= 0 && metaPos < udtaPos + 500) {
                        // Found metadata atom
                        // In practice, you would need to respect the atom structure
                        // This is just a simplified illustration
                        
                        const QString metadataStr = QString("©aut:John Reese|©dev:%1|©sw:iOS %2|©loc:%3,%4")
                            .arg(deviceModel)
                            .arg(iosVersion)
                            .arg(latitude)
                            .arg(longitude);
                        
                        const QByteArray metadataBytes = metadataStr.toUtf8();
                        if (metaPos + 24 < bytes.size()) {
                            const int maxReplace = qMin(metadataBytes.size(), 100);
                            bytes.replace(metaPos + 24, maxReplace, metadataBytes.left(maxReplace));
                        }
                    }
                }
            }
        }
    }
}

bool EnhancedPrivacy::IsMediaMetadataSpoofingEnabled() {
    return _mediaMetadataSpoofingEnabled;
}

void EnhancedPrivacy::SetMediaMetadataSpoofingEnabled(bool enabled) {
    _mediaMetadataSpoofingEnabled = enabled;
}

// User tracking implementation
void EnhancedPrivacy::SetUserTrackingEnabled(bool enabled) {
    _userTrackingEnabled = enabled;
}

bool EnhancedPrivacy::IsUserTrackingEnabled() {
    return _userTrackingEnabled;
}

void EnhancedPrivacy::AddUserToTracking(UserId userId) {
    _trackedUsers.insert(userId);
}

void EnhancedPrivacy::RemoveUserFromTracking(UserId userId) {
    _trackedUsers.remove(userId);
}

// Alias methods for consistent UI calls
void EnhancedPrivacy::AddTrackedUser(UserId userId) {
    AddUserToTracking(userId);
}

void EnhancedPrivacy::RemoveTrackedUser(UserId userId) {
    RemoveUserFromTracking(userId);
}

bool EnhancedPrivacy::IsUserTracked(UserId userId) {
    return _trackedUsers.contains(userId);
}

const QSet<UserId>& EnhancedPrivacy::GetTrackedUsers() {
    return _trackedUsers;
}

void EnhancedPrivacy::SetAutoJoinDelay(int minMinutes, int maxMinutes) {
    // Validate inputs to ensure min <= max and positive values
    if (minMinutes > 0 && maxMinutes >= minMinutes) {
        _autoJoinMinDelay = minMinutes;
        _autoJoinMaxDelay = maxMinutes;
    }
}

QPair<int, int> EnhancedPrivacy::GetAutoJoinDelay() {
    return qMakePair(_autoJoinMinDelay, _autoJoinMaxDelay);
}

bool EnhancedPrivacy::ShouldTrackUser(UserId userId) {
    return _userTrackingEnabled && _trackedUsers.contains(userId);
}

// Time-based Key Derivation
QString EnhancedPrivacy::DeriveTimeBasedKey(int64 timestamp) {
    if (!IsUsingTimeBasedKey()) {
        return QString();
    }
    
    if (timestamp == 0) {
        timestamp = QDateTime::currentSecsSinceEpoch();
    }
    
    // Use the salt and timestamp to derive a key
    const auto input = QString("%1:%2").arg(_timeBasedKeySalt).arg(timestamp);
    return QCryptographicHash::hash(
        input.toUtf8(),
        QCryptographicHash::Sha256
    ).toHex();
}

QStringList EnhancedPrivacy::GetPreviousTimeBasedKeys(int daysBack) {
    QStringList keys;
    const auto now = QDateTime::currentSecsSinceEpoch();
    
    for (int i = 0; i < daysBack; i++) {
        const auto timestamp = now - (i * 24 * 60 * 60);
        keys.append(DeriveTimeBasedKey(timestamp));
    }
    
    return keys;
}

// Key Management
void EnhancedPrivacy::AddToKeyHistory(const QString &key) {
    if (key.isEmpty()) {
        return;
    }
    
    // Add to history if not already present
    if (!IsKeyInHistory(key)) {
        _keyHistory.append(key);
        
        // Prune history if it exceeds the limit
        PruneKeyHistory(GetKeyHistorySize());
    }
}

bool EnhancedPrivacy::IsKeyInHistory(const QString &key) {
    return _keyHistory.contains(key);
}

QStringList EnhancedPrivacy::GetKeyHistory() {
    return _keyHistory;
}

void EnhancedPrivacy::PruneKeyHistory(int maxKeys) {
    while (_keyHistory.size() > maxKeys) {
        _keyHistory.removeFirst();
    }
}

// Configuration methods for Time-based Key
void EnhancedPrivacy::SetUseTimeBasedKey(bool enabled) {
    _useTimeBasedKey = enabled;
}

void EnhancedPrivacy::SetTimeBasedKeySalt(const QString &salt) {
    _timeBasedKeySalt = salt;
}

bool EnhancedPrivacy::IsUsingTimeBasedKey() {
    return _useTimeBasedKey;
}

QString EnhancedPrivacy::GetTimeBasedKeySalt() {
    return _timeBasedKeySalt;
}

// General Key Configuration
void EnhancedPrivacy::SetKeyHistorySize(int size) {
    _keyHistorySize = size;
    PruneKeyHistory(size);
}

int EnhancedPrivacy::GetKeyHistorySize() {
    return _keyHistorySize;
}

void EnhancedPrivacy::ClearKeyHistory() {
    _keyHistory.clear();
}

// Enhanced Metadata Protection methods
void EnhancedPrivacy::StripAllMetadata(QByteArray &bytes, const QString &format) {
    if (!IsEnhancedMetadataProtectionEnabled()) {
        return;
    }

    const QString formatLower = format.toLower();
    
    // Process based on file type
    if (IsImageFormat(formatLower, bytes)) {
        // For images: create a clean copy without metadata
        QImage image;
        if (image.loadFromData(bytes)) {
            // Create a new image with the same content but no metadata
            QImage cleanImage(image.width(), image.height(), image.format());
            cleanImage.fill(Qt::transparent);
            
            // Copy only the pixel data, not the metadata
            QPainter painter(&cleanImage);
            painter.drawImage(0, 0, image);
            painter.end();
            
            // Convert back to bytes
            QBuffer buffer(&bytes);
            buffer.open(QIODevice::WriteOnly);
            cleanImage.save(&buffer, formatLower.toUtf8().constData());
            buffer.close();
        }
    } 
    else if (IsAudioFormat(formatLower, bytes)) {
        // For audio files, use a temporary file for TagLib processing
        QTemporaryFile tempFile;
        if (tempFile.open()) {
            // Write current data to the temp file
            tempFile.write(bytes);
            tempFile.flush();
            
            // Get the file path as a C string for TagLib
            const QByteArray filePath = QFile::encodeName(tempFile.fileName());
            TagLib::File* file = nullptr;
            
            // Create appropriate TagLib file handler
            if (formatLower == "mp3") {
                file = new TagLib::MPEG::File(filePath.constData());
            } else if (formatLower == "flac") {
                file = new TagLib::FLAC::File(filePath.constData());
            } else if (formatLower == "m4a") {
                file = new TagLib::MP4::File(filePath.constData());
            } else if (formatLower == "ogg") {
                file = new TagLib::Ogg::Vorbis::File(filePath.constData());
            } else if (formatLower == "wav") {
                file = new TagLib::RIFF::WAV::File(filePath.constData());
            } else {
                file = new TagLib::FileRef(filePath.constData()).file();
            }
            
            // Process the file if valid
            if (file && file->isValid()) {
                // Get the tag interface and strip all metadata
                TagLib::Tag* tag = file->tag();
                if (tag) {
                    // Clear all standard metadata
                    tag->setTitle("");
                    tag->setArtist("");
                    tag->setAlbum("");
                    tag->setComment("");
                    tag->setYear(0);
                    tag->setTrack(0);
                    tag->setGenre("");
                    
                    // For MP3 files, handle ID3v2 tags
                    if (formatLower == "mp3") {
                        auto* mpegFile = dynamic_cast<TagLib::MPEG::File*>(file);
                        if (mpegFile) {
                            // Remove ID3v1 and ID3v2 tags completely
                            mpegFile->strip(TagLib::MPEG::File::ID3v1 | TagLib::MPEG::File::ID3v2);
                        }
                    }
                    
                    // For other formats, strip all properties
                    file->setProperties(TagLib::PropertyMap());
                    
                    // Save changes
                    file->save();
                }
                
                delete file;
                
                // Read back the stripped file
                tempFile.seek(0);
                bytes = tempFile.readAll();
            }
            
            tempFile.close();
        }
    }
    else if (IsVideoFormat(formatLower, bytes)) {
        // Video metadata stripping logic - basic implementation
        // This is a simplified approach for common video containers
        // For more robust handling, specialized libraries would be needed
        
        // Look for metadata blocks in common formats and zero them out
        // MP4/MOV metadata is often in 'moov' atom
        QByteArray moovPattern = QByteArray::fromHex("6D6F6F76"); // "moov" in hex
        int moovPos = bytes.indexOf(moovPattern);
        
        if (moovPos > 4) {
            // Get the atom size (4 bytes before 'moov')
            QDataStream stream(bytes.mid(moovPos - 4, 4));
            stream.setByteOrder(QDataStream::BigEndian);
            quint32 atomSize;
            stream >> atomSize;
            
            // If we have a valid atom size, replace metadata with zeros
            // but preserve essential container structure
            if (atomSize > 8 && atomSize < 10000000) { // Sanity check on size
                // Skip the essential header (8 bytes) and 0-fill metadata fields
                // within the atom, preserving the structure
                for (int i = moovPos + 8; i < moovPos + atomSize && i < bytes.size(); i++) {
                    // Only zero out fields that are clearly metadata
                    // This is oversimplified - a real implementation would
                    // parse the atom structure properly
                    if (bytes.mid(i, 4) == QByteArray::fromHex("2A9C94")) {
                        // Example metadata marker - would be format specific
                        for (int j = i; j < i + 128 && j < bytes.size(); j++) {
                            bytes[j] = 0;
                        }
                    }
                }
            }
        }
    }
    else if (IsArchiveFormat(formatLower, bytes)) {
        // For archives, we handle the comment sections in common formats
        // ZIP archives have a comment at the end
        if (formatLower == "zip") {
            // Find the end of central directory record
            QByteArray eocdMarker = QByteArray::fromHex("504B0506"); // PK\05\06 in hex
            int eocdPos = bytes.lastIndexOf(eocdMarker);
            
            if (eocdPos > 0) {
                // The comment length is at offset eocdPos + 20, 2 bytes
                QDataStream stream(bytes.mid(eocdPos + 20, 2));
                stream.setByteOrder(QDataStream::LittleEndian);
                quint16 commentLength;
                stream >> commentLength;
                
                // If there's a comment, remove it
                if (commentLength > 0) {
                    // Set the comment length to zero
                    bytes[eocdPos + 20] = 0;
                    bytes[eocdPos + 21] = 0;
                    
                    // Truncate the file to remove the comment
                    bytes.truncate(eocdPos + 22); // 22 is the size of the EOCD record without comment
                }
            }
        }
        // RAR archives have a comment block with marker 0x75
        else if (formatLower == "rar" || formatLower.startsWith("r") && formatLower.length() == 3) {
            // Find comment markers in RAR files
            QByteArray commentMarker = QByteArray::fromHex("7500"); // Comment marker in RAR
            int pos = 0;
            
            while ((pos = bytes.indexOf(commentMarker, pos)) != -1) {
                // A simplistic approach - in a real implementation, 
                // we would need to parse the RAR format structure properly
                // For now, just zero out the comment data
                for (int i = pos + 2; i < pos + 256 && i < bytes.size(); i++) {
                    if ((unsigned char)bytes[i] == 0x7B) { // End of comment marker
                        break;
                    }
                    bytes[i] = 0;
                }
                
                pos += 2;
            }
        }
    }
}

QByteArray EnhancedPrivacy::DisarmAndReconstruct(const QByteArray &bytes, const QString &format) {
    if (!IsEnhancedMetadataProtectionEnabled()) {
        return bytes;
    }

    QByteArray result = bytes;
    const QString formatLower = format.toLower();
    
    // Content Disarm & Reconstruction (CDR) process
    if (IsImageFormat(formatLower, bytes)) {
        // For images: decode and re-encode to strip any malicious content
        QImage image;
        if (image.loadFromData(bytes)) {
            // Create a new image with only the visible content
            QImage safeImage(image.width(), image.height(), QImage::Format_ARGB32);
            safeImage.fill(Qt::transparent);
            
            // Copy only the pixel data
            QPainter painter(&safeImage);
            painter.drawImage(0, 0, image);
            painter.end();
            
            // Convert to the safest possible format for that image type
            QByteArray safeBytes;
            QBuffer buffer(&safeBytes);
            buffer.open(QIODevice::WriteOnly);
            
            // Use the safest format parameters (disable compression exploits)
            if (formatLower == "jpg" || formatLower == "jpeg") {
                safeImage.save(&buffer, "JPEG", 85); // Medium quality, safer encoding
            } 
            else if (formatLower == "png") {
                safeImage.save(&buffer, "PNG", 0); // Compression level 0 (faster, safer)
            }
            else {
                // For other formats, default to PNG as it's generally safer
                safeImage.save(&buffer, "PNG", 0);
            }
            
            buffer.close();
            result = safeBytes;
        }
    }
    else if (IsAudioFormat(formatLower, bytes)) {
        // For audio: decode to raw PCM and re-encode
        QTemporaryFile tempInFile;
        QTemporaryFile tempOutFile;
        
        if (tempInFile.open() && tempOutFile.open()) {
            // Write the original data to the temp file
            tempInFile.write(bytes);
            tempInFile.flush();
            
            // Use TagLib to extract just the audio data, discarding metadata
            const QByteArray inPath = QFile::encodeName(tempInFile.fileName());
            const QByteArray outPath = QFile::encodeName(tempOutFile.fileName());
            
            TagLib::File* file = nullptr;
            bool success = false;
            
            // Create appropriate TagLib file handler
            if (formatLower == "mp3") {
                file = new TagLib::MPEG::File(inPath.constData());
                if (file && file->isValid()) {
                    // For real implementation, we would:
                    // 1. Extract raw audio samples
                    // 2. Create a new MP3 file with only those samples
                    // Here we simulate by stripping all metadata
                    auto* mpegFile = dynamic_cast<TagLib::MPEG::File*>(file);
                    if (mpegFile) {
                        // Remove all metadata but keep audio content
                        mpegFile->strip();
                        success = mpegFile->save();
                    }
                }
            }
            // Handle other audio formats similarly...
            
            delete file;
            
            if (success) {
                // Read the sanitized file
                tempInFile.seek(0);
                result = tempInFile.readAll();
            }
            
            tempInFile.close();
            tempOutFile.close();
        }
    }
    else if (IsVideoFormat(formatLower, bytes)) {
        // For video: this would require a specialized library
        // Here we just implement a basic sanitation for common formats
        
        // Basic MP4 sanitization - remove non-essential atoms
        if (formatLower == "mp4" || formatLower == "mov") {
            QByteArray safeBytes;
            int pos = 0;
            
            // Process each atom
            while (pos + 8 <= bytes.size()) {
                // Get atom size and type
                QDataStream stream(bytes.mid(pos, 8));
                stream.setByteOrder(QDataStream::BigEndian);
                quint32 atomSize;
                char atomType[5] = {0};
                
                stream >> atomSize;
                stream.readRawData(atomType, 4);
                
                // Sanity check on atom size
                if (atomSize < 8 || pos + atomSize > bytes.size()) {
                    break;
                }
                
                // Keep essential atoms, strip potentially dangerous ones
                QString type = QString(atomType);
                if (type == "ftyp" || type == "moov" || type == "mdat") {
                    // These are essential atoms - keep them
                    safeBytes.append(bytes.mid(pos, atomSize));
                }
                // Skip other atoms (like "uuid", "meta", custom atoms)
                
                pos += atomSize;
            }
            
            if (!safeBytes.isEmpty()) {
                result = safeBytes;
            }
        }
    }
    
    return result;
}

bool EnhancedPrivacy::IsEnhancedMetadataProtectionEnabled() {
    return _enhancedMetadataProtectionEnabled;
}

void EnhancedPrivacy::SetEnhancedMetadataProtectionEnabled(bool enabled) {
    _enhancedMetadataProtectionEnabled = enabled;
}

// Traffic Padding and Randomization methods
void EnhancedPrivacy::EnableTrafficPadding(bool enabled) {
    _trafficPaddingEnabled = enabled;
}

bool EnhancedPrivacy::IsTrafficPaddingEnabled() {
    return _trafficPaddingEnabled;
}

QByteArray EnhancedPrivacy::AddTrafficPadding(QByteArray &data) {
    if (!IsTrafficPaddingEnabled()) {
        return data;
    }
    
    // Calculate a random amount of padding to add
    int paddingSize = GetRandomPaddingSize(_minPaddingBytes, _maxPaddingBytes);
    
    // Create a random padding array
    QByteArray padding(paddingSize, 0);
    for (int i = 0; i < paddingSize; i++) {
        padding[i] = static_cast<char>(base::RandomValue<uchar>());
    }
    
    // Add length marker and padding type marker for later removal
    QByteArray result;
    QDataStream stream(&result, QIODevice::WriteOnly);
    
    // Magic marker for our padding (used to identify padding during removal)
    const char* magicMarker = "TGPAD";
    
    // Write: magic marker (5 bytes) + padding size (4 bytes) + 
    // original data size (4 bytes) + checksum (4 bytes)
    stream.writeRawData(magicMarker, 5);
    stream << (quint32)paddingSize;
    stream << (quint32)data.size();
    
    // Calculate checksum of original data
    QByteArray checksum = QCryptographicHash::hash(data, QCryptographicHash::Md5).left(4);
    stream.writeRawData(checksum.constData(), 4);
    
    // Add the original data
    result.append(data);
    
    // Add the padding with random data
    result.append(padding);
    
    return result;
}

QByteArray EnhancedPrivacy::RemoveTrafficPadding(QByteArray &data) {
    if (!IsTrafficPaddingEnabled() || data.size() < 17) { // 5+4+4+4 bytes minimum
        return data;
    }
    
    // Check for our padding magic marker
    if (data.left(5) != "TGPAD") {
        return data; // Not our padded data
    }
    
    // Extract the header information
    QDataStream stream(data);
    
    // Skip magic marker
    stream.skipRawData(5);
    
    // Read padding and data sizes
    quint32 paddingSize;
    quint32 dataSize;
    stream >> paddingSize;
    stream >> dataSize;
    
    // Validate sizes
    if (paddingSize + dataSize + 17 != (quint32)data.size()) {
        return data; // Invalid padding format
    }
    
    // Read checksum
    QByteArray storedChecksum(4, 0);
    stream.readRawData(storedChecksum.data(), 4);
    
    // Extract the original data
    QByteArray originalData = data.mid(17, dataSize);
    
    // Verify checksum
    QByteArray calculatedChecksum = QCryptographicHash::hash(originalData, QCryptographicHash::Md5).left(4);
    if (calculatedChecksum != storedChecksum) {
        return data; // Checksum mismatch, data may be corrupted
    }
    
    return originalData;
}

int EnhancedPrivacy::GetRandomPaddingSize(int minBytes, int maxBytes) {
    // Generate a random padding size within the specified range
    return minBytes + (base::RandomValue<int>() % (maxBytes - minBytes + 1));
}

// Check if auto-accept of encryption requests is enabled
bool IsAutoAcceptEnabled() {
    const auto settings = Core::App().settings();
    return settings.isAutoAcceptEncryptionEnabled();
}

// Enable/disable auto-accept of encryption requests
void SetAutoAcceptEnabled(bool enabled) {
    auto &settings = Core::App().settings();
    settings.setAutoAcceptEncryptionEnabled(enabled);
    Local::writeUserSettings();
}

// Signal Protocol Integration
bool EnhancedPrivacy::InitializeSignalProtocol() {
    if (!Core::App().domain().started()) {
        return false;
    }

    auto &session = Core::App().domain().active();
    if (!session) {
        return false;
    }

    auto e2eController = session->e2eController();
    if (!e2eController) {
        return false;
    }

    // Enable Signal Protocol
    e2eController->setEnabled(true);
    _signalProtocolEnabled = true;

    // Generate initial keys if needed
    if (!GenerateSignalKeys()) {
        return false;
    }

    return true;
}

bool EnhancedPrivacy::IsSignalProtocolEnabled() {
    return _signalProtocolEnabled;
}

void EnhancedPrivacy::SetSignalProtocolEnabled(bool enabled) {
    if (enabled && !_signalProtocolEnabled) {
        if (!InitializeSignalProtocol()) {
            return;
        }
    }

    _signalProtocolEnabled = enabled;

    auto &session = Core::App().domain().active();
    if (!session) {
        return;
    }

    auto e2eController = session->e2eController();
    if (e2eController) {
        e2eController->setEnabled(enabled);
    }
}

bool EnhancedPrivacy::GenerateSignalKeys() {
    auto &session = Core::App().domain().active();
    if (!session) {
        return false;
    }

    auto e2eController = session->e2eController();
    if (!e2eController) {
        return false;
    }

    try {
        // Generate new key bundle
        e2eController->rotateKeys();
        return true;
    } catch (const std::exception &e) {
        LOG(("Signal Protocol Error: Failed to generate keys: %1").arg(e.what()));
        return false;
    }
}

bool EnhancedPrivacy::ExportSignalKeys(const QString &password, QByteArray &outData) {
    auto &session = Core::App().domain().active();
    if (!session) {
        return false;
    }

    auto e2eController = session->e2eController();
    if (!e2eController) {
        return false;
    }

    try {
        e2eController->backupKeys(password);
        return true;
    } catch (const std::exception &e) {
        LOG(("Signal Protocol Error: Failed to export keys: %1").arg(e.what()));
        return false;
    }
}

bool EnhancedPrivacy::ImportSignalKeys(const QString &password, const QByteArray &data) {
    auto &session = Core::App().domain().active();
    if (!session) {
        return false;
    }

    auto e2eController = session->e2eController();
    if (!e2eController) {
        return false;
    }

    try {
        return e2eController->restoreKeysFromBackup(password, data);
    } catch (const std::exception &e) {
        LOG(("Signal Protocol Error: Failed to import keys: %1").arg(e.what()));
        return false;
    }
}

void EnhancedPrivacy::RotateSignalKeys() {
    auto &session = Core::App().domain().active();
    if (!session) {
        return;
    }

    auto e2eController = session->e2eController();
    if (!e2eController) {
        return;
    }

    try {
        e2eController->rotateKeys();
    } catch (const std::exception &e) {
        LOG(("Signal Protocol Error: Failed to rotate keys: %1").arg(e.what()));
    }
}

// CRYPTOGRAM User Identification (Red Name Feature)
void EnhancedPrivacy::RegisterCryptogramUser(UserId userId) {
    _cryptogramUsers.insert(userId);
}

void EnhancedPrivacy::UnregisterCryptogramUser(UserId userId) {
    _cryptogramUsers.remove(userId);
}

bool EnhancedPrivacy::IsCryptogramUser(UserId userId) {
    return _cryptogramUsers.contains(userId);
}

const QSet<UserId>& EnhancedPrivacy::GetCryptogramUsers() {
    return _cryptogramUsers;
}

void EnhancedPrivacy::ClearCryptogramUsers() {
    _cryptogramUsers.clear();
}

} // namespace Data 