/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/flags.h"
#include "chat_helpers/compose/compose_features.h"
#include "data/data_types.h"
#include "history/history.h"
#include "ui/text/text_custom_emoji.h"
#include <QtCore/QMap>
#include <QtCore/QString>
#include <QtCore/QStringList>
#include <QtCore/QVector>
#include <QtCore/QCryptographicHash>

// Properly handle TagLib availability
#ifdef HAVE_TAGLIB
// Include the real TagLib headers using proper include paths
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
#else
// Define stub TagLib classes when TagLib is not available
namespace TagLib {
    class FileRef {
    public:
        FileRef() {}
        explicit FileRef(const char*) {}
        bool isNull() const { return true; }
    };
    
    class Tag {
    public:
        virtual ~Tag() {}
        virtual QString title() const { return QString(); }
        virtual void setTitle(const QString&) {}
        virtual QString artist() const { return QString(); }
        virtual void setArtist(const QString&) {}
        virtual QString album() const { return QString(); }
        virtual void setAlbum(const QString&) {}
        virtual QString comment() const { return QString(); }
        virtual void setComment(const QString&) {}
        virtual QString genre() const { return QString(); }
        virtual void setGenre(const QString&) {}
        virtual unsigned int year() const { return 0; }
        virtual void setYear(unsigned int) {}
        virtual unsigned int track() const { return 0; }
        virtual void setTrack(unsigned int) {}
    };
    
    class PropertyMap {
    public:
        PropertyMap() {}
        bool isEmpty() const { return true; }
    };
}
#endif // HAVE_TAGLIB 

namespace Data {

class EnhancedPrivacy {
public:
	EnhancedPrivacy() = default;
	EnhancedPrivacy(const EnhancedPrivacy &other) = delete;
	EnhancedPrivacy &operator=(const EnhancedPrivacy &other) = delete;
	~EnhancedPrivacy() = default;

    // Encryption methods
    static TextWithEntities EncryptMessage(const TextWithEntities &original, const QString &passphrase);
    static TextWithEntities DecryptMessage(const TextWithEntities &encrypted);
    static bool IsEncrypted(const TextWithEntities &text);
    
    // Configuration methods
    static void SetEncryptionEnabled(bool enabled);
    static void SetEncryptionPassphrase(const QString &passphrase);
    static bool IsEncryptionEnabled();
    static QString GetEncryptionPassphrase();

    // Time-based Key Derivation
    static QString DeriveTimeBasedKey(int64 timestamp = 0);
    static QStringList GetPreviousTimeBasedKeys(int daysBack = 7);
    static void SetUseTimeBasedKey(bool enabled);
    static void SetTimeBasedKeySalt(const QString &salt);
    static bool IsUsingTimeBasedKey();
    static QString GetTimeBasedKeySalt();

    // Signal Protocol Integration
    static bool InitializeSignalProtocol();
    static bool IsSignalProtocolEnabled();
    static void SetSignalProtocolEnabled(bool enabled);
    static bool GenerateSignalKeys();
    static bool ExportSignalKeys(const QString &password, QByteArray &outData);
    static bool ImportSignalKeys(const QString &password, const QByteArray &data);
    static void RotateSignalKeys();

    // General Key Configuration
    static void SetKeyHistorySize(int size);
    static int GetKeyHistorySize();
    static void ClearKeyHistory();

    // Metadata injection settings
    static void SetMetadataInjectionEnabled(bool enabled);
    static bool IsMetadataInjectionEnabled();

    // Metadata injection into messages
    static TextWithEntities InjectMetadata(const TextWithEntities &original);
    static QString GenerateRandomMetadata();

    // Keyboard input method switching for sensitive messages
    static void SetKeyboardSwitchingEnabled(bool enabled);
    static bool IsKeyboardSwitchingEnabled();
    static void RandomizeKeyboardLayout(TextWithEntities &text);
    static QString SwitchKeyboardLayout(const QString &text, int segments = 2);
    static QString SwitchToLayout(const QString &text, const QString &layout);

    // Media metadata spoofing
    static void SetMediaMetadataSpoofingEnabled(bool enabled);
    static bool IsMediaMetadataSpoofingEnabled();
    static void SpoofMediaMetadata(QImage &image, QByteArray &bytes, const QString &format);

    // User tracking protection
    static void SetUserTrackingEnabled(bool enabled);
    static bool IsUserTrackingEnabled();
    static void AddUserToTracking(UserId userId);
    static void RemoveUserFromTracking(UserId userId);
    static void AddTrackedUser(UserId userId);  // UI alias
    static void RemoveTrackedUser(UserId userId);  // UI alias
    static bool IsUserTracked(UserId userId);
    static const QSet<UserId>& GetTrackedUsers();
    static void SetAutoJoinDelay(int minMinutes, int maxMinutes);
    static QPair<int, int> GetAutoJoinDelay();
    static bool ShouldTrackUser(UserId userId);

    // Enhanced Metadata Protection - new methods
    static void StripAllMetadata(QByteArray &bytes, const QString &format);
    static QByteArray DisarmAndReconstruct(const QByteArray &bytes, const QString &format);
    static bool IsEnhancedMetadataProtectionEnabled();
    static void SetEnhancedMetadataProtectionEnabled(bool enabled);
    
    // Traffic Padding and Randomization - new methods
    static void EnableTrafficPadding(bool enabled);
    static bool IsTrafficPaddingEnabled();
    static QByteArray AddTrafficPadding(QByteArray &data);
    static QByteArray RemoveTrafficPadding(QByteArray &data);
    static int GetRandomPaddingSize(int minBytes, int maxBytes);

    // Check if auto-accept of key exchange requests is enabled
    static bool IsAutoAcceptEnabled();
    static void SetAutoAcceptEnabled(bool enabled);

    // CRYPTOGRAM User Identification (Red Name Feature)
    static void RegisterCryptogramUser(UserId userId);
    static void UnregisterCryptogramUser(UserId userId);
    static bool IsCryptogramUser(UserId userId);
    static const QSet<UserId>& GetCryptogramUsers();
    static void ClearCryptogramUsers();

private:
    static bool _enhancedMetadataProtectionEnabled;
    static bool _trafficPaddingEnabled;
    static int _minPaddingBytes;
    static int _maxPaddingBytes;
    static bool _signalProtocolEnabled;
    static QSet<UserId> _cryptogramUsers;  // Registry of known CRYPTOGRAM users
};

} // namespace Data 