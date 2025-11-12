/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "data/data_peer.h"
#include "data/data_session.h"
#include "data/data_user.h"
#include "mtproto/mtproto_auth_key.h"

#include <QtCore/QDateTime>
#include <QtCore/QMap>
#include <QtCore/QSet>
#include <QtCore/QVector>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>

namespace Data {

struct CanaryToken {
    enum class TokenType {
        Message,        // Message-based canary tokens
        File,           // File/document based canary tokens
        Link,           // URL-based canary tokens
        ContactCard,    // Contact card based canary tokens
        ProfileView     // Profile view based canary tokens
    };
    
    // Token identification
    QString id;                     // Unique identifier
    TokenType type;                 // Type of token
    QString description;            // User-provided description
    QDateTime created;              // Creation timestamp
    
    // Token placement information
    PeerId placementPeerId;         // Where token was placed (chat/channel)
    MsgId placementMsgId;           // Message ID if relevant
    QString placementContext;       // Additional context about placement
    
    // Trigger information
    bool triggered = false;         // Whether the token has been triggered
    QDateTime triggerTime;          // When it was triggered
    QString triggerDetails;         // Details about the trigger (IP, user-agent)
    UserId triggeredBy;             // If known, who triggered it
    
    // Notification settings
    bool notifyOnTrigger = true;    // Whether to notify on trigger
    QString notificationMethod;     // How to notify (in-app, email, etc)
    
    // Serialization methods
    QByteArray serialize() const;
    static CanaryToken deserialize(const QByteArray &data);
    
    // Generate a unique canary token ID
    static QString generateTokenId();
};

struct HoneypotData {
    enum class DataType {
        Contact,        // Fake contact information
        Document,       // Fake document/file 
        Message,        // Fake message content
        Account,        // Fake account information
        Location        // Fake location data
    };
    
    // Data identification
    QString id;                     // Unique identifier
    DataType type;                  // Type of honeypot data
    QString description;            // User-provided description
    QDateTime created;              // Creation timestamp
    
    // Honeypot content
    QVariantMap content;            // The actual honeypot data
    QString fingerprint;            // Unique fingerprint for this data
    
    // Placement information
    PeerId placementPeerId;         // Where data was placed
    MsgId placementMsgId;           // Message ID if relevant
    
    // Access tracking
    QVector<QPair<UserId, QDateTime>> accessLog; // Who accessed and when
    
    // Attractiveness score (how likely it is to be targeted)
    int attractivenessScore = 5;    // 1-10 scale
    
    // Serialization methods
    QByteArray serialize() const;
    static HoneypotData deserialize(const QByteArray &data);
    
    // Generate a unique honeypot data ID
    static QString generateDataId();
    
    // Generate honeypot fingerprint
    static QString generateFingerprint(const QVariantMap &content);
};

struct AttributedAdversary {
    // Identification
    QString id;                         // Unique identifier
    QString name;                       // Name or label
    int confidenceScore = 0;            // 0-100 confidence in attribution
    QDateTime firstObserved;            // When first observed
    QDateTime lastActive;               // When last active
    
    // Group affiliation
    QString groupId;                    // Group this adversary belongs to
    
    // Technical indicators
    QStringList ipAddresses;            // Associated IP addresses
    QStringList deviceFingerprints;     // Device fingerprints
    QSet<UserId> associatedUserIds;     // Associated user IDs
    
    // Behavioral patterns
    QMap<QString, int> activityTimes;   // Time patterns (hour -> frequency)
    QMap<QString, int> languagePatterns;// Language patterns (lang -> frequency)
    QStringList topicsOfInterest;       // Topics frequently accessed
    
    // Attribution confidence factors
    struct ConfidenceFactor {
        QString factor;                 // Name of the factor
        int weight;                     // Weight in overall confidence
        QString explanation;            // Explanation of this factor
    };
    QVector<ConfidenceFactor> confidenceFactors;
    
    // Tactics observed
    QStringList observedTactics;        // Tactics observed
    
    // Serialization methods
    QByteArray serialize() const;
    static AttributedAdversary deserialize(const QByteArray &data);
    
    // Generate a unique adversary ID
    static QString generateAdversaryId();
    
    // Calculate confidence score based on factors
    void recalculateConfidenceScore();
};

// Adversary Group structure
struct AdversaryGroup {
    // Group identification
    QString id;                         // Unique identifier
    QString name;                       // Name of the group
    QString description;                // Description of the group
    QDateTime created;                  // Creation timestamp
    
    // Visual representation
    QColor color;                       // Color assigned to this group for UI
    QString emoji;                      // Emoji identifier for quick visual recognition
    
    // Membership and relationships
    QStringList memberIds;              // IDs of adversaries in this group
    QMap<QString, int> relationToGroups;// Relationships to other groups (groupId -> strength)
    
    // Group detection confidence
    int cohesionScore = 0;              // 0-100 score of how confident we are these are related
    
    // Serialization methods
    QByteArray serialize() const;
    static AdversaryGroup deserialize(const QByteArray &data);
    
    // Generate a unique group ID
    static QString generateGroupId();
    
    // Generate a distinct color for this group
    static QColor generateGroupColor(const QString &groupId);
    
    // Calculate cohesion score based on member relationships
    void recalculateCohesionScore();
};

// Structure to track suspicious message patterns
struct SuspiciousPattern {
    enum class TacticType {
        Reciprocity,
        Scarcity,
        Authority,
        Consistency,
        SocialProof,
        Liking,
        Urgency,
        FearAppeal,
        Deception,
        CredentialHarvesting,
        Unknown
    };
    
    TacticType tacticType = TacticType::Unknown;
    int suspicionLevel = 0;  // 1-10 scale
    QString explanation;      // Human-readable explanation
    QColor highlightColor;   // Color for UI highlighting
    QString tacticName;      // Display name of the tactic
    QVector<QPair<int, int>> textRanges;  // Ranges to highlight in message
    bool isActive = true;    // Whether this pattern is currently considered active
    QDateTime detectedTime;  // When this pattern was first detected
    
    // Helper to create a standardized highlight color based on suspicion level
    static QColor getSuspicionColor(int level) {
        // Create colors that get more intense with higher suspicion levels
        // Using a gradient from yellow (low) through orange to red (high)
        if (level <= 3) {
            return QColor(255, 255, 100, 40 + level * 20);  // Light yellow
        } else if (level <= 6) {
            return QColor(255, 200 - (level - 3) * 20, 50, 100 + level * 20);  // Orange
        } else {
            return QColor(255, 100 - (level - 7) * 20, 50, 160 + level * 20);  // Red
        }
    }
};

// Structure to track message-level social engineering analysis
struct MessageSuspicionInfo {
    MsgId messageId;
    QVector<SuspiciousPattern> patterns;
    int overallSuspicionLevel = 0;  // Highest pattern level
    QDateTime analyzedTime;
    bool requiresAttention = false;  // Flag for patterns that need immediate attention
    
    // Calculate the overall suspicion level based on patterns
    void updateOverallSuspicion() {
        overallSuspicionLevel = 0;
        for (const auto &pattern : patterns) {
            if (pattern.isActive) {
                overallSuspicionLevel = qMax(overallSuspicionLevel, pattern.suspicionLevel);
            }
        }
        // Mark for attention if suspicion level is high
        requiresAttention = overallSuspicionLevel >= 8;
    }
};

// Main class for counterintelligence features
class CounterIntelligenceManager : public QObject {
    Q_OBJECT
    
public:
    CounterIntelligenceManager();
    
    // Canary token system
    CanaryToken createCanaryToken(
        CanaryToken::TokenType type,
        const QString &description,
        PeerId placementPeerId = PeerId(0));
    
    void placeCanaryToken(
        const QString &tokenId,
        PeerId placementPeerId,
        MsgId placementMsgId = MsgId(0),
        const QString &placementContext = QString());
    
    void deleteCanaryToken(const QString &tokenId);
    CanaryToken getCanaryToken(const QString &tokenId) const;
    QVector<CanaryToken> getAllCanaryTokens() const;
    QVector<CanaryToken> getTriggeredCanaryTokens() const;
    
    // Event when a canary token is triggered
    rpl::producer<CanaryToken> canaryTokenTriggered() const;
    
    // Check if a message/file/link contains a canary token
    bool isCanaryToken(const MTPMessage &message) const;
    bool isCanaryToken(const QString &url) const;
    bool isCanaryToken(const DocumentData *document) const;
    
    // Honeypot data system
    HoneypotData createHoneypotData(
        HoneypotData::DataType type,
        const QString &description,
        const QVariantMap &content,
        PeerId placementPeerId = PeerId(0));
    
    void placeHoneypotData(
        const QString &dataId,
        PeerId placementPeerId,
        MsgId placementMsgId = MsgId(0));
    
    void deleteHoneypotData(const QString &dataId);
    HoneypotData getHoneypotData(const QString &dataId) const;
    QVector<HoneypotData> getAllHoneypotData() const;
    
    // Log access to honeypot data
    void logHoneypotAccess(const QString &dataId, UserId accessedBy);
    
    // Event when honeypot data is accessed
    rpl::producer<QPair<HoneypotData, UserId>> honeypotDataAccessed() const;
    
    // Generate believable honeypot data
    QVariantMap generateHoneypotContact() const;
    QVariantMap generateHoneypotDocument(const QString &documentType) const;
    QVariantMap generateHoneypotMessage(const QString &topic) const;
    QVariantMap generateHoneypotAccount() const;
    QVariantMap generateHoneypotLocation() const;

    // Enhanced location randomization integration
    QVariantMap generateHoneypotLocationWithContext(const QString &context = QString()) const;
    void setLocationRandomizationManager(class LocationRandomizationManager *lrm);

    // Adversary attribution
    AttributedAdversary createAdversary(
        const QString &name,
        const QStringList &indicators = QStringList());
    
    void updateAdversaryActivity(
        const QString &adversaryId,
        UserId userId = UserId(0),
        const QString &ipAddress = QString());
    
    void deleteAdversary(const QString &adversaryId);
    AttributedAdversary getAdversary(const QString &adversaryId) const;
    QVector<AttributedAdversary> getAllAdversaries() const;
    
    // Attempt to attribute an action to a known adversary
    QPair<AttributedAdversary, int> attributeAction(
        UserId userId,
        const QString &ipAddress,
        const QString &deviceFingerprint);
    
    // Event when a new attribution is made
    rpl::producer<AttributedAdversary> newAttributionMade() const;
    
    // General settings
    void setNotificationEnabled(bool enabled);
    bool isNotificationEnabled() const;
    
    void setAutoAttribution(bool enabled);
    bool isAutoAttribution() const;
    
    void setCollectionThreshold(int threshold);
    int collectionThreshold() const;
    
    // Set endpoint for external notification
    void setWebhookEndpoint(const QString &url, const QString &apiKey);
    QString webhookEndpoint() const;
    
    // Load/save state
    void saveState();
    void loadState();
    
    // Adversary Group methods
    AdversaryGroup createGroup(const QString &name, const QString &description);
    void updateGroup(const AdversaryGroup &group);
    void deleteGroup(const QString &groupId);
    AdversaryGroup getGroup(const QString &groupId) const;
    QVector<AdversaryGroup> getAllGroups() const;
    
    // Add or remove adversaries from groups
    void addAdversaryToGroup(const QString &adversaryId, const QString &groupId);
    void removeAdversaryFromGroup(const QString &adversaryId, const QString &groupId);
    
    // Auto-grouping of adversaries based on shared characteristics
    void autoGroupAdversaries(int similarityThreshold = 60);
    
    // Get color for a user based on group membership
    QColor getUserColor(UserId userId) const;
    QString getUserGroupEmoji(UserId userId) const;
    
    // Event when groups are updated
    rpl::producer<AdversaryGroup> groupUpdated() const;
    
    // Social engineering pattern highlighting
    MessageSuspicionInfo analyzeMessageForSuspiciousPatterns(
        const QString &messageText,
        MsgId messageId,
        UserId senderId);
    
    QVector<SuspiciousPattern> getActivePatternsForMessage(MsgId messageId) const;
    
    // Event when new suspicious patterns are detected
    rpl::producer<MessageSuspicionInfo> suspiciousPatternDetected() const;
    
    // Get explanation for a specific pattern
    QString getPatternExplanation(SuspiciousPattern::TacticType type) const;
    
    // Update pattern status
    void updatePatternStatus(MsgId messageId, int patternIndex, bool isActive);
    
    // Get all suspicious messages for a user
    QVector<MessageSuspicionInfo> getSuspiciousMessagesForUser(UserId userId) const;
    
private:
    // Canary token methods
    void triggerCanaryToken(
        const QString &tokenId,
        UserId triggeredBy = UserId(0),
        const QString &triggerDetails = QString());
    
    QString createCallbackUrl(const QString &tokenId) const;
    void checkCallbackEndpoint();
    
    // Honeypot analysis
    void analyzeHoneypotAccess();
    
    // Attribution methods
    void correlateAdversaries();
    void updateTacticsAttribution();
    
    // Helper methods
    void notifyOnTrigger(const CanaryToken &token);
    void sendWebhookNotification(const QString &eventType, const QVariantMap &eventData);
    
    // Group analysis methods
    void mergeGroups(const QString &groupId1, const QString &groupId2);
    void updateGroupRelationships();
    int calculateAdversarySimilarity(const AttributedAdversary &a, const AttributedAdversary &b) const;
    
    // Advanced social engineering analysis methods
    void analyzeSocialEngineeringBehavior(
        const AttributedAdversary &adversary,
        QMap<QString, int> &ttpEvidence);
    
    void analyzeConversationDynamics(
        const ConversationMetrics &metrics,
        const QMap<QString, int> &manipulationCounts,
        QMap<QString, int> &ttpEvidence);
    
    void analyzeCrossUserPatterns(
        const QMap<UserId, ConversationMetrics> &userMetrics,
        QMap<QString, int> &ttpEvidence);
    
    double calculateConsistencyScore(const QVector<double> &values);
    
    // Social engineering pattern analysis
    QVector<SuspiciousPattern> detectSuspiciousPatterns(
        const QString &messageText,
        const ConversationMetrics &metrics);
    
    int calculatePatternSuspicionLevel(
        const QString &messageText,
        SuspiciousPattern::TacticType tacticType,
        const ConversationMetrics &metrics);
    
    QString generatePatternExplanation(
        SuspiciousPattern::TacticType tacticType,
        int suspicionLevel,
        const QVector<QString> &evidencePoints);
    
    // Storage
    QMap<QString, CanaryToken> _canaryTokens;
    QMap<QString, HoneypotData> _honeypotData;
    QMap<QString, AttributedAdversary> _adversaries;
    QMap<QString, AdversaryGroup> _adversaryGroups;
    
    // Network
    std::unique_ptr<QNetworkAccessManager> _networkManager;
    
    // Settings
    bool _notificationsEnabled = true;
    bool _autoAttributionEnabled = true;
    int _collectionThreshold = 3;  // Default threshold for collection detection
    QString _webhookUrl;
    QString _webhookApiKey;
    
    // Event streams
    rpl::event_stream<CanaryToken> _canaryTokenTriggeredStream;
    rpl::event_stream<QPair<HoneypotData, UserId>> _honeypotAccessedStream;
    rpl::event_stream<AttributedAdversary> _newAttributionStream;
    rpl::event_stream<AdversaryGroup> _groupUpdatedStream;
    
    // Storage for suspicious patterns
    QMap<MsgId, MessageSuspicionInfo> _messageSuspicionInfo;
    QMap<UserId, QVector<MsgId>> _userSuspiciousMessages;
    
    // Event stream for suspicious patterns
    rpl::event_stream<MessageSuspicionInfo> _suspiciousPatternStream;

    // Location randomization integration
    class LocationRandomizationManager *_locationRandomizationManager = nullptr;
};

} // namespace Data 