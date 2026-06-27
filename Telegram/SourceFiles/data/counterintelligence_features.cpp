/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "data/counterintelligence_features.h"
#include "data/data_location_randomization.h"

#include "apiwrap.h"
#include "data/data_session.h"
#include "data/data_user.h"
#include "lang/lang_keys.h"
#include "main/main_session.h"
#include "mtproto/mtproto_auth_key.h"
#include "storage/localstorage.h"
#include "storage/storage_account.h"
#include "ui/text/text_utilities.h"

#include <QtCore/QCryptographicHash>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QJsonArray>
#include <QtCore/QUuid>
#include <QtNetwork/QNetworkRequest>

namespace Data {

namespace {

// Constants
constexpr auto kCanaryTokensKey = "canary_tokens";
constexpr auto kHoneypotDataKey = "honeypot_data";
constexpr auto kAdversariesKey = "attributed_adversaries";
constexpr auto kCounterIntelSettingsKey = "counter_intel_settings";
constexpr auto kDefaultCallbackUrl = "https://canarytokens.org/api/v1/callback/";

// Helper to generate a cryptographically strong random identifier
QString generateSecureId() {
    const auto randomData = MTP::AuthKey::Data::Generate(16);
    return QCryptographicHash::hash(
        QByteArray::fromRawData(
            reinterpret_cast<const char*>(randomData.data()),
            randomData.size()),
        QCryptographicHash::Sha256).toHex();
}

// Generate HMAC for creating secure tokens
QByteArray generateHMAC(const QByteArray &data, const QByteArray &key) {
    return QMessageAuthenticationCode::hash(
        data, 
        key,
        QCryptographicHash::Sha256);
}

} // namespace

//
// CanaryToken implementation
//

QString CanaryToken::generateTokenId() {
    return QUuid::createUuid().toString(QUuid::WithoutBraces);
}

QByteArray CanaryToken::serialize() const {
    QJsonObject json;
    json["id"] = id;
    json["type"] = static_cast<int>(type);
    json["description"] = description;
    json["created"] = created.toString(Qt::ISODate);
    
    json["placementPeerId"] = QString::number(placementPeerId.value);
    json["placementMsgId"] = QString::number(placementMsgId.bare);
    json["placementContext"] = placementContext;
    
    json["triggered"] = triggered;
    if (triggered && !triggerTime.isNull()) {
        json["triggerTime"] = triggerTime.toString(Qt::ISODate);
        json["triggerDetails"] = triggerDetails;
        json["triggeredBy"] = QString::number(triggeredBy.value);
    }
    
    json["notifyOnTrigger"] = notifyOnTrigger;
    json["notificationMethod"] = notificationMethod;
    
    return QJsonDocument(json).toJson(QJsonDocument::Compact);
}

CanaryToken CanaryToken::deserialize(const QByteArray &data) {
    CanaryToken result;
    const auto json = QJsonDocument::fromJson(data).object();
    
    result.id = json["id"].toString();
    result.type = static_cast<TokenType>(json["type"].toInt());
    result.description = json["description"].toString();
    result.created = QDateTime::fromString(json["created"].toString(), Qt::ISODate);
    
    result.placementPeerId = PeerId(json["placementPeerId"].toString().toLongLong());
    result.placementMsgId = MsgId(json["placementMsgId"].toString().toInt());
    result.placementContext = json["placementContext"].toString();
    
    result.triggered = json["triggered"].toBool();
    if (result.triggered) {
        result.triggerTime = QDateTime::fromString(json["triggerTime"].toString(), Qt::ISODate);
        result.triggerDetails = json["triggerDetails"].toString();
        result.triggeredBy = UserId(json["triggeredBy"].toString().toLongLong());
    }
    
    result.notifyOnTrigger = json["notifyOnTrigger"].toBool();
    result.notificationMethod = json["notificationMethod"].toString();
    
    return result;
}

//
// HoneypotData implementation
//

QString HoneypotData::generateDataId() {
    return QUuid::createUuid().toString(QUuid::WithoutBraces);
}

QString HoneypotData::generateFingerprint(const QVariantMap &content) {
    QJsonDocument doc(QJsonObject::fromVariantMap(content));
    return QCryptographicHash::hash(
        doc.toJson(QJsonDocument::Compact),
        QCryptographicHash::Sha256).toHex();
}

QByteArray HoneypotData::serialize() const {
    QJsonObject json;
    json["id"] = id;
    json["type"] = static_cast<int>(type);
    json["description"] = description;
    json["created"] = created.toString(Qt::ISODate);
    
    json["content"] = QJsonObject::fromVariantMap(content);
    json["fingerprint"] = fingerprint;
    
    json["placementPeerId"] = QString::number(placementPeerId.value);
    json["placementMsgId"] = QString::number(placementMsgId.bare);
    
    QJsonArray accessLogArray;
    for (const auto &entry : accessLog) {
        QJsonObject logEntry;
        logEntry["userId"] = QString::number(entry.first.value);
        logEntry["timestamp"] = entry.second.toString(Qt::ISODate);
        accessLogArray.append(logEntry);
    }
    json["accessLog"] = accessLogArray;
    
    json["attractivenessScore"] = attractivenessScore;
    
    return QJsonDocument(json).toJson(QJsonDocument::Compact);
}

HoneypotData HoneypotData::deserialize(const QByteArray &data) {
    HoneypotData result;
    const auto json = QJsonDocument::fromJson(data).object();
    
    result.id = json["id"].toString();
    result.type = static_cast<DataType>(json["type"].toInt());
    result.description = json["description"].toString();
    result.created = QDateTime::fromString(json["created"].toString(), Qt::ISODate);
    
    result.content = json["content"].toObject().toVariantMap();
    result.fingerprint = json["fingerprint"].toString();
    
    result.placementPeerId = PeerId(json["placementPeerId"].toString().toLongLong());
    result.placementMsgId = MsgId(json["placementMsgId"].toString().toInt());
    
    const auto accessLogArray = json["accessLog"].toArray();
    for (const auto &entry : accessLogArray) {
        const auto entryObj = entry.toObject();
        UserId userId(entryObj["userId"].toString().toLongLong());
        QDateTime timestamp = QDateTime::fromString(entryObj["timestamp"].toString(), Qt::ISODate);
        result.accessLog.append(qMakePair(userId, timestamp));
    }
    
    result.attractivenessScore = json["attractivenessScore"].toInt();
    
    return result;
}

//
// AttributedAdversary implementation
//

QString AttributedAdversary::generateAdversaryId() {
    return QUuid::createUuid().toString(QUuid::WithoutBraces);
}

void AttributedAdversary::recalculateConfidenceScore() {
    if (confidenceFactors.isEmpty()) {
        confidenceScore = 0;
        return;
    }
    
    int totalWeight = 0;
    int weightedSum = 0;
    
    for (const auto &factor : confidenceFactors) {
        totalWeight += factor.weight;
        weightedSum += factor.weight;
    }
    
    if (totalWeight > 0) {
        confidenceScore = (weightedSum * 100) / totalWeight;
        // Clamp to 0-100 range
        confidenceScore = qBound(0, confidenceScore, 100);
    } else {
        confidenceScore = 0;
    }
}

QByteArray AttributedAdversary::serialize() const {
    QJsonObject json;
    json["id"] = id;
    json["name"] = name;
    json["confidenceScore"] = confidenceScore;
    json["firstObserved"] = firstObserved.toString(Qt::ISODate);
    json["lastActive"] = lastActive.toString(Qt::ISODate);
    
    // Group affiliation
    json["groupId"] = groupId;
    
    // Technical indicators
    QJsonArray ipArray;
    for (const auto &ip : ipAddresses) {
        ipArray.append(ip);
    }
    json["ipAddresses"] = ipArray;
    
    QJsonArray fingerprintArray;
    for (const auto &fingerprint : deviceFingerprints) {
        fingerprintArray.append(fingerprint);
    }
    json["deviceFingerprints"] = fingerprintArray;
    
    QJsonArray userIdArray;
    for (const auto &userId : associatedUserIds) {
        userIdArray.append(QString::number(userId.value));
    }
    json["associatedUserIds"] = userIdArray;
    
    // Behavioral patterns
    QJsonObject activityTimesObj;
    for (auto it = activityTimes.constBegin(); it != activityTimes.constEnd(); ++it) {
        activityTimesObj[it.key()] = it.value();
    }
    json["activityTimes"] = activityTimesObj;
    
    QJsonObject languagePatternsObj;
    for (auto it = languagePatterns.constBegin(); it != languagePatterns.constEnd(); ++it) {
        languagePatternsObj[it.key()] = it.value();
    }
    json["languagePatterns"] = languagePatternsObj;
    
    QJsonArray topicsArray;
    for (const auto &topic : topicsOfInterest) {
        topicsArray.append(topic);
    }
    json["topicsOfInterest"] = topicsArray;
    
    // Confidence factors
    QJsonArray confidenceFactorsArray;
    for (const auto &factor : confidenceFactors) {
        QJsonObject factorObj;
        factorObj["factor"] = factor.factor;
        factorObj["weight"] = factor.weight;
        factorObj["explanation"] = factor.explanation;
        confidenceFactorsArray.append(factorObj);
    }
    json["confidenceFactors"] = confidenceFactorsArray;
    
    // Tactics
    QJsonArray tacticsArray;
    for (const auto &tactic : observedTactics) {
        tacticsArray.append(tactic);
    }
    json["observedTactics"] = tacticsArray;
    
    return QJsonDocument(json).toJson(QJsonDocument::Compact);
}

AttributedAdversary AttributedAdversary::deserialize(const QByteArray &data) {
    AttributedAdversary result;
    const auto json = QJsonDocument::fromJson(data).object();
    
    result.id = json["id"].toString();
    result.name = json["name"].toString();
    result.confidenceScore = json["confidenceScore"].toInt();
    result.firstObserved = QDateTime::fromString(json["firstObserved"].toString(), Qt::ISODate);
    result.lastActive = QDateTime::fromString(json["lastActive"].toString(), Qt::ISODate);
    
    // Group affiliation
    result.groupId = json["groupId"].toString();
    
    // Technical indicators
    const auto ipArray = json["ipAddresses"].toArray();
    for (const auto &ip : ipArray) {
        result.ipAddresses.append(ip.toString());
    }
    
    const auto fingerprintArray = json["deviceFingerprints"].toArray();
    for (const auto &fingerprint : fingerprintArray) {
        result.deviceFingerprints.append(fingerprint.toString());
    }
    
    const auto userIdArray = json["associatedUserIds"].toArray();
    for (const auto &userId : userIdArray) {
        result.associatedUserIds.insert(UserId(userId.toString().toLongLong()));
    }
    
    // Behavioral patterns
    const auto activityTimesObj = json["activityTimes"].toObject();
    for (auto it = activityTimesObj.constBegin(); it != activityTimesObj.constEnd(); ++it) {
        result.activityTimes[it.key()] = it.value().toInt();
    }
    
    const auto languagePatternsObj = json["languagePatterns"].toObject();
    for (auto it = languagePatternsObj.constBegin(); it != languagePatternsObj.constEnd(); ++it) {
        result.languagePatterns[it.key()] = it.value().toInt();
    }
    
    const auto topicsArray = json["topicsOfInterest"].toArray();
    for (const auto &topic : topicsArray) {
        result.topicsOfInterest.append(topic.toString());
    }
    
    // Confidence factors
    const auto confidenceFactorsArray = json["confidenceFactors"].toArray();
    for (const auto &factorJson : confidenceFactorsArray) {
        const auto factorObj = factorJson.toObject();
        AttributedAdversary::ConfidenceFactor factor;
        factor.factor = factorObj["factor"].toString();
        factor.weight = factorObj["weight"].toInt();
        factor.explanation = factorObj["explanation"].toString();
        result.confidenceFactors.append(factor);
    }
    
    // Tactics
    const auto tacticsArray = json["observedTactics"].toArray();
    for (const auto &tactic : tacticsArray) {
        result.observedTactics.append(tactic.toString());
    }
    
    return result;
}

//
// AdversaryGroup implementation
//

QString AdversaryGroup::generateGroupId() {
    return QUuid::createUuid().toString(QUuid::WithoutBraces);
}

QColor AdversaryGroup::generateGroupColor(const QString &groupId) {
    // Generate a deterministic but distinct color based on the groupId
    // This ensures the same group always gets the same color
    
    // Use the groupId hash to seed the color generation
    const auto hash = QCryptographicHash::hash(
        groupId.toUtf8(),
        QCryptographicHash::Sha256);
    
    // Extract bytes from the hash for RGB values
    // Using different positions to ensure color diversity
    const int r = qBound(60, static_cast<int>(hash[0]) % 220 + 35, 220);
    const int g = qBound(60, static_cast<int>(hash[3]) % 220 + 35, 220);
    const int b = qBound(60, static_cast<int>(hash[6]) % 220 + 35, 220);
    
    // Create a color with sufficient contrast for text display
    return QColor(r, g, b);
}

void AdversaryGroup::recalculateCohesionScore() {
    if (memberIds.isEmpty()) {
        cohesionScore = 0;
        return;
    }
    
    // Basic implementation - more complex scoring would analyze
    // the relationships between members more thoroughly
    
    // For now, base the score on the number of members and
    // the strength of relationships with other groups
    int totalRelationStrength = 0;
    for (auto it = relationToGroups.constBegin(); it != relationToGroups.constEnd(); ++it) {
        totalRelationStrength += it.value();
    }
    
    // Calculate the cohesion score based on members and relationships
    const int memberFactor = qMin(80, memberIds.count() * 10);
    const int relationFactor = relationToGroups.isEmpty() 
        ? 0 
        : qMin(20, totalRelationStrength / relationToGroups.size());
    
    cohesionScore = memberFactor + relationFactor;
    cohesionScore = qBound(0, cohesionScore, 100);
}

QByteArray AdversaryGroup::serialize() const {
    QJsonObject json;
    json["id"] = id;
    json["name"] = name;
    json["description"] = description;
    json["created"] = created.toString(Qt::ISODate);
    
    // Color and emoji
    json["color"] = color.name();
    json["emoji"] = emoji;
    
    // Members
    QJsonArray memberArray;
    for (const auto &memberId : memberIds) {
        memberArray.append(memberId);
    }
    json["memberIds"] = memberArray;
    
    // Relations to other groups
    QJsonObject relationsObj;
    for (auto it = relationToGroups.constBegin(); it != relationToGroups.constEnd(); ++it) {
        relationsObj[it.key()] = it.value();
    }
    json["relationToGroups"] = relationsObj;
    
    json["cohesionScore"] = cohesionScore;
    
    return QJsonDocument(json).toJson(QJsonDocument::Compact);
}

AdversaryGroup AdversaryGroup::deserialize(const QByteArray &data) {
    AdversaryGroup result;
    const auto json = QJsonDocument::fromJson(data).object();
    
    result.id = json["id"].toString();
    result.name = json["name"].toString();
    result.description = json["description"].toString();
    result.created = QDateTime::fromString(json["created"].toString(), Qt::ISODate);
    
    // Color and emoji
    result.color = QColor(json["color"].toString());
    result.emoji = json["emoji"].toString();
    
    // Members
    const auto memberArray = json["memberIds"].toArray();
    for (const auto &member : memberArray) {
        result.memberIds.append(member.toString());
    }
    
    // Relations to other groups
    const auto relationsObj = json["relationToGroups"].toObject();
    for (auto it = relationsObj.constBegin(); it != relationsObj.constEnd(); ++it) {
        result.relationToGroups[it.key()] = it.value().toInt();
    }
    
    result.cohesionScore = json["cohesionScore"].toInt();
    
    return result;
}

//
// CounterIntelligenceManager implementation
//

CounterIntelligenceManager::CounterIntelligenceManager() 
    : _networkManager(std::make_unique<QNetworkAccessManager>()) {
    
    // Load saved state
    loadState();
    
    // Set up network manager
    connect(_networkManager.get(), &QNetworkAccessManager::finished,
        this, [this](QNetworkReply *reply) {
            const auto url = reply->url().toString();
            
            // Handle callback from canary token service
            if (url.contains(kDefaultCallbackUrl)) {
                const auto tokenId = url.split("/").last();
                if (!tokenId.isEmpty() && _canaryTokens.contains(tokenId)) {
                    // Extract trigger details
                    const auto data = reply->readAll();
                    triggerCanaryToken(tokenId, UserId(0), QString::fromUtf8(data));
                }
            }
            
            reply->deleteLater();
        });
    
    // Check callback endpoint
    checkCallbackEndpoint();
}

// Canary token methods

CanaryToken CounterIntelligenceManager::createCanaryToken(
    CanaryToken::TokenType type,
    const QString &description,
    PeerId placementPeerId) {
    
    CanaryToken token;
    token.id = CanaryToken::generateTokenId();
    token.type = type;
    token.description = description;
    token.created = QDateTime::currentDateTime();
    token.placementPeerId = placementPeerId;
    
    // Default notification method is in-app
    token.notificationMethod = "in-app";
    
    // Store the token
    _canaryTokens[token.id] = token;
    
    // Save state
    saveState();
    
    return token;
}

void CounterIntelligenceManager::placeCanaryToken(
    const QString &tokenId,
    PeerId placementPeerId,
    MsgId placementMsgId,
    const QString &placementContext) {
    
    if (!_canaryTokens.contains(tokenId)) {
        return;
    }
    
    auto &token = _canaryTokens[tokenId];
    token.placementPeerId = placementPeerId;
    token.placementMsgId = placementMsgId;
    token.placementContext = placementContext;
    
    // Save state
    saveState();
}

void CounterIntelligenceManager::deleteCanaryToken(const QString &tokenId) {
    if (_canaryTokens.contains(tokenId)) {
        _canaryTokens.remove(tokenId);
        saveState();
    }
}

CanaryToken CounterIntelligenceManager::getCanaryToken(const QString &tokenId) const {
    return _canaryTokens.value(tokenId);
}

QVector<CanaryToken> CounterIntelligenceManager::getAllCanaryTokens() const {
    QVector<CanaryToken> result;
    for (const auto &token : _canaryTokens) {
        result.append(token);
    }
    return result;
}

QVector<CanaryToken> CounterIntelligenceManager::getTriggeredCanaryTokens() const {
    QVector<CanaryToken> result;
    for (const auto &token : _canaryTokens) {
        if (token.triggered) {
            result.append(token);
        }
    }
    return result;
}

rpl::producer<CanaryToken> CounterIntelligenceManager::canaryTokenTriggered() const {
    return _canaryTokenTriggeredStream.events();
}

void CounterIntelligenceManager::triggerCanaryToken(
    const QString &tokenId,
    UserId triggeredBy,
    const QString &triggerDetails) {
    
    if (!_canaryTokens.contains(tokenId)) {
        return;
    }
    
    auto &token = _canaryTokens[tokenId];
    token.triggered = true;
    token.triggerTime = QDateTime::currentDateTime();
    token.triggerDetails = triggerDetails;
    token.triggeredBy = triggeredBy;
    
    // Fire the event
    _canaryTokenTriggeredStream.fire_copy(token);
    
    // Notify if enabled
    if (token.notifyOnTrigger && _notificationsEnabled) {
        notifyOnTrigger(token);
    }
    
    // Save state
    saveState();
}

QString CounterIntelligenceManager::createCallbackUrl(const QString &tokenId) const {
    return QString("%1%2").arg(kDefaultCallbackUrl, tokenId);
}

void CounterIntelligenceManager::checkCallbackEndpoint() {
    // Periodically check if the canary token service is responding
    auto request = QNetworkRequest(QUrl(kDefaultCallbackUrl));
    _networkManager->get(request);
}

void CounterIntelligenceManager::notifyOnTrigger(const CanaryToken &token) {
    // In-app notification logic using Telegram's notification system
    if (_notificationsEnabled) {
        // Create notification content
        auto notification = std::make_shared<Data::SecurityNotification>();
        notification->type = Data::SecurityNotification::Type::CanaryTokenTriggered;
        notification->title = "Canary Token Triggered";
        
        // Build notification message
        auto message = QString("A canary token has been triggered.\n\n");
        message += QString("Description: %1\n").arg(token.description);
        message += QString("Type: %1\n").arg([&]() -> QString {
            switch (token.type) {
                case CanaryToken::TokenType::Message: return "Message";
                case CanaryToken::TokenType::File: return "File";
                case CanaryToken::TokenType::Link: return "Link";
                case CanaryToken::TokenType::ContactCard: return "Contact Card";
                case CanaryToken::TokenType::ProfileView: return "Profile View";
                default: return "Unknown";
            }
        }());
        
        // Add trigger details if available
        if (!token.triggerDetails.isEmpty()) {
            message += QString("Details: %1\n").arg(token.triggerDetails);
        }
        
        // Add timestamp
        message += QString("Time: %1").arg(token.triggerTime.toString("yyyy-MM-dd hh:mm:ss"));
        
        notification->message = message;
        
        // Add actions to the notification
        notification->actions.push_back({
            .text = "View Details",
            .type = Data::SecurityNotification::Action::Type::Custom,
            .data = QVariant::fromValue(token.id)
        });
        
        notification->actions.push_back({
            .text = "Ignore",
            .type = Data::SecurityNotification::Action::Type::Dismiss
        });
        
        // Set notification priority based on attractiveness/importance of the token
        notification->priority = Data::SecurityNotification::Priority::Critical;
        
        // Duration - keep until explicitly dismissed
        notification->duration = -1;
        
        // Sound alert
        notification->playSound = true;
        
        // Create and set a unique identifier for this notification
        notification->uniqueId = QString("canary_%1").arg(token.id);
        
        // Add to session notifications
        if (Core::App().activeAccount().sessionExists()) {
            auto &session = Core::App().activeAccount().session();
            session.notifications().securityNotificationAdded(notification);
            
            // Show the notification immediately if possible
            session.notifications().showSecurityNotification(notification->uniqueId);
            
            // Log the trigger event
            session.securityLog().logEvent(
                Data::SecurityLogEvent::Type::CanaryTokenTriggered,
                QVariantMap{
                    {"token_id", token.id},
                    {"token_description", token.description},
                    {"trigger_time", token.triggerTime.toString(Qt::ISODate)},
                }
            );
        }
    }
    
    // If webhook is configured, send notification there
    if (!_webhookUrl.isEmpty()) {
        QVariantMap eventData;
        eventData["event"] = "canary_triggered";
        eventData["token_id"] = token.id;
        eventData["token_type"] = static_cast<int>(token.type);
        eventData["description"] = token.description;
        eventData["trigger_time"] = token.triggerTime.toString(Qt::ISODate);
        eventData["trigger_details"] = token.triggerDetails;
        
        sendWebhookNotification("canary_token_triggered", eventData);
    }
}

void CounterIntelligenceManager::sendWebhookNotification(
    const QString &eventType,
    const QVariantMap &eventData) {
    
    if (_webhookUrl.isEmpty()) {
        return;
    }
    
    QJsonObject json;
    json["event_type"] = eventType;
    json["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);
    json["data"] = QJsonObject::fromVariantMap(eventData);
    
    // Add API key if configured
    if (!_webhookApiKey.isEmpty()) {
        json["api_key"] = _webhookApiKey;
    }
    
    QNetworkRequest request(QUrl(_webhookUrl));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    
    _networkManager->post(request, QJsonDocument(json).toJson());
}

// Settings methods

void CounterIntelligenceManager::setNotificationEnabled(bool enabled) {
    _notificationsEnabled = enabled;
    saveState();
}

bool CounterIntelligenceManager::isNotificationEnabled() const {
    return _notificationsEnabled;
}

void CounterIntelligenceManager::setAutoAttribution(bool enabled) {
    _autoAttributionEnabled = enabled;
    saveState();
}

bool CounterIntelligenceManager::isAutoAttribution() const {
    return _autoAttributionEnabled;
}

void CounterIntelligenceManager::setCollectionThreshold(int threshold) {
    _collectionThreshold = threshold;
    saveState();
}

int CounterIntelligenceManager::collectionThreshold() const {
    return _collectionThreshold;
}

void CounterIntelligenceManager::setWebhookEndpoint(
    const QString &url,
    const QString &apiKey) {
    
    _webhookUrl = url;
    _webhookApiKey = apiKey;
    saveState();
}

QString CounterIntelligenceManager::webhookEndpoint() const {
    return _webhookUrl;
}

// State persistence

void CounterIntelligenceManager::saveState() {
    QVariantMap state;
    
    // Save canary tokens
    QVariantList canaryTokensList;
    for (const auto &token : _canaryTokens) {
        canaryTokensList.append(token.serialize());
    }
    state["canary_tokens"] = canaryTokensList;
    
    // Save honeypot data
    QVariantList honeypotDataList;
    for (const auto &data : _honeypotData) {
        honeypotDataList.append(data.serialize());
    }
    state["honeypot_data"] = honeypotDataList;
    
    // Save adversaries
    QVariantList adversariesList;
    for (const auto &adversary : _adversaries) {
        adversariesList.append(adversary.serialize());
    }
    state["adversaries"] = adversariesList;
    
    // Save adversary groups
    QVariantList groupsList;
    for (const auto &group : _adversaryGroups) {
        groupsList.append(group.serialize());
    }
    state["adversary_groups"] = groupsList;
    
    // Save settings
    QVariantMap settings;
    settings["notifications_enabled"] = _notificationsEnabled;
    settings["auto_attribution_enabled"] = _autoAttributionEnabled;
    settings["collection_threshold"] = _collectionThreshold;
    settings["webhook_url"] = _webhookUrl;
    settings["webhook_api_key"] = _webhookApiKey;
    state["settings"] = settings;
    
    // Save to local storage
    Local::writeCustomSetting(kCounterIntelSettingsKey, QJsonDocument::fromVariant(state).toJson());
}

void CounterIntelligenceManager::loadState() {
    const auto data = Local::readCustomSetting(kCounterIntelSettingsKey);
    if (data.isEmpty()) {
        return;
    }
    
    const auto state = QJsonDocument::fromJson(data).toVariant().toMap();
    
    // Load canary tokens
    const auto canaryTokensList = state["canary_tokens"].toList();
    for (const auto &tokenData : canaryTokensList) {
        const auto token = CanaryToken::deserialize(tokenData.toByteArray());
        _canaryTokens[token.id] = token;
    }
    
    // Load honeypot data
    const auto honeypotDataList = state["honeypot_data"].toList();
    for (const auto &dataItem : honeypotDataList) {
        const auto honeypotData = HoneypotData::deserialize(dataItem.toByteArray());
        _honeypotData[honeypotData.id] = honeypotData;
    }
    
    // Load adversaries
    const auto adversariesList = state["adversaries"].toList();
    for (const auto &adversaryData : adversariesList) {
        const auto adversary = AttributedAdversary::deserialize(adversaryData.toByteArray());
        _adversaries[adversary.id] = adversary;
    }
    
    // Load adversary groups
    const auto groupsList = state["adversary_groups"].toList();
    for (const auto &groupData : groupsList) {
        const auto group = AdversaryGroup::deserialize(groupData.toByteArray());
        _adversaryGroups[group.id] = group;
    }
    
    // Load settings
    const auto settings = state["settings"].toMap();
    _notificationsEnabled = settings["notifications_enabled"].toBool();
    _autoAttributionEnabled = settings["auto_attribution_enabled"].toBool();
    _collectionThreshold = settings["collection_threshold"].toInt();
    _webhookUrl = settings["webhook_url"].toString();
    _webhookApiKey = settings["webhook_api_key"].toString();
}

// Check if a message, URL, or document contains a canary token
bool CounterIntelligenceManager::isCanaryToken(const MTPMessage &message) const {
    // Extract message content and metadata
    if (message.type() == mtpc_message || message.type() == mtpc_messageService) {
        const auto &data = message.c_message();
        
        // Check message text for embedded tokens
        if (const auto text = data.vmessage()) {
            const auto messageText = qs(*text);
            
            // Look for URL-based canary tokens in the message
            static const QRegularExpression urlRegex(
                R"(https?://[^\s/$.?#].[^\s]*)",
                QRegularExpression::CaseInsensitiveOption);
            
            auto iterator = urlRegex.globalMatch(messageText);
            while (iterator.hasNext()) {
                auto match = iterator.next();
                if (isCanaryToken(match.captured(0))) {
                    return true;
                }
            }
        }
        
        // Check for canary tokens in media
        if (const auto media = data.vmedia()) {
            const auto mediaType = media->type();
            
            // Check documents
            if (mediaType == mtpc_messageMediaDocument) {
                const auto &mediaDocument = media->c_messageMediaDocument();
                if (const auto document = mediaDocument.vdocument()) {
                    // Generate a document fingerprint
                    const auto documentId = document->c_document().vid().v;
                    const auto accessHash = document->c_document().vaccess_hash().v;
                    
                    // Check if this document ID is a canary
                    for (const auto &token : _canaryTokens) {
                        if (token.type == CanaryToken::TokenType::File) {
                            // For file tokens, we would store document IDs in the placeholder context
                            if (token.placementContext.contains(QString::number(documentId))) {
                                return true;
                            }
                        }
                    }
                }
            }
            
            // Check contact cards
            else if (mediaType == mtpc_messageMediaContact) {
                const auto &contact = media->c_messageMediaContact();
                if (const auto phoneNumber = contact.vphone_number()) {
                    const auto phone = qs(*phoneNumber);
                    
                    // Check if this phone number is a canary
                    for (const auto &token : _canaryTokens) {
                        if (token.type == CanaryToken::TokenType::ContactCard) {
                            if (token.placementContext.contains(phone)) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        
        // Check if the entire message is a canary token
        for (const auto &token : _canaryTokens) {
            if (token.type == CanaryToken::TokenType::Message &&
                token.placementPeerId == PeerId(data.vpeer_id()) &&
                token.placementMsgId == MsgId(data.vid().v)) {
                return true;
            }
        }
    }
    
    return false;
}

bool CounterIntelligenceManager::isCanaryToken(const QString &url) const {
    // Check if this URL matches any of our canary tokens
    for (const auto &token : _canaryTokens) {
        if (token.type == CanaryToken::TokenType::Link) {
            // For link tokens, check multiple components:
            
            // 1. Direct match on the callback URL
            if (url.contains(createCallbackUrl(token.id))) {
                return true;
            }
            
            // 2. Check if URL contains token ID in path or query parameters
            if (url.contains(token.id)) {
                return true;
            }
            
            // 3. Check for custom URL patterns stored in placement context
            if (!token.placementContext.isEmpty()) {
                const auto patterns = token.placementContext.split(',', Qt::SkipEmptyParts);
                for (const auto &pattern : patterns) {
                    if (url.contains(pattern.trimmed())) {
                        return true;
                    }
                }
            }
            
            // 4. Apply HMAC verification for secure tokens
            // Extract token signature if present in URL query parameters
            QUrl parsedUrl(url);
            const auto queryItems = QUrlQuery(parsedUrl).queryItems();
            for (const auto &item : queryItems) {
                if (item.first == "token" || item.first == "id" || item.first == "sig") {
                    // Verify the signature matches our token
                    const auto signature = item.second;
                    
                    // Reconstruct the expected signature using the base URL and our token ID
                    const auto baseUrl = parsedUrl.toString(QUrl::RemoveQuery);
                    const auto expectedSignature = QCryptographicHash::hash(
                        (baseUrl + token.id).toUtf8(),
                        QCryptographicHash::Sha256).toHex();
                    
                    // Check for a partial match (we use partial to allow for URL shorteners)
                    if (signature.contains(expectedSignature.left(16)) || 
                        expectedSignature.contains(signature.left(16))) {
                        return true;
                    }
                }
            }
        }
    }
    return false;
}

bool CounterIntelligenceManager::isCanaryToken(const DocumentData *document) const {
    if (!document) {
        return false;
    }
    
    // Check if this document matches any of our file-based canary tokens
    for (const auto &token : _canaryTokens) {
        if (token.type == CanaryToken::TokenType::File) {
            // Document matching uses multiple techniques:
            
            // 1. Match by document ID
            if (token.placementContext.contains(QString::number(document->id))) {
                return true;
            }
            
            // 2. Filename matching for honeytokens
            if (!document->filename().isEmpty() && 
                token.placementContext.contains(document->filename())) {
                return true;
            }
            
            // 3. MIME type pattern matching
            const auto mimeType = document->mimeString();
            if (!mimeType.isEmpty() && token.placementContext.contains(mimeType)) {
                return true;
            }
            
            // 4. Check for embedded markers in document metadata
            // This is implemented by checking known metadata locations based on file type
            if (document->loaded()) {
                // Get file data
                const auto &fileData = document->data();
                
                // Check by document type
                if (document->isImage()) {
                    // Check for EXIF metadata in images
                    const auto exifData = Media::ReadExifData(fileData);
                    
                    // Check for canary markers in common EXIF fields
                    for (const auto &[field, value] : exifData.fields) {
                        // Check if any EXIF field contains our token ID or other markers
                        if (value.toString().contains(token.id) || 
                            token.placementContext.contains(value.toString())) {
                            return true;
                        }
                    }
                    
                    // Check for steganographic markers in image files
                    const auto lsbData = Media::ExtractLSBData(fileData);
                    if (!lsbData.isEmpty() && 
                        (lsbData.contains(token.id) || token.placementContext.contains(lsbData))) {
                        return true;
                    }
                    
                } else if (document->mimeString().contains("pdf")) {
                    // For PDF files, check for metadata in the PDF document
                    const auto pdfMetadata = Media::ReadPdfMetadata(fileData);
                    
                    // Check standard PDF metadata fields
                    for (const auto &[field, value] : pdfMetadata) {
                        if (value.toString().contains(token.id) || 
                            token.placementContext.contains(value.toString())) {
                            return true;
                        }
                    }
                    
                } else if (document->mimeString().contains("officedocument")) {
                    // For Microsoft Office documents, check for metadata
                    const auto officeMetadata = Media::ReadOfficeMetadata(fileData);
                    
                    // Check standard Office metadata fields
                    for (const auto &[field, value] : officeMetadata) {
                        if (value.toString().contains(token.id) || 
                            token.placementContext.contains(value.toString())) {
                            return true;
                        }
                    }
                }
                
                // Check for custom canary markers in binary files
                // These would be pre-defined byte patterns encoded in the file
                static const QStringList CANARY_MARKERS = {
                    "CNRY", "TKID", "SPYGRAM_CANARY", "MONITORED_FILE"
                };
                
                const auto fileString = QString::fromUtf8(
                    reinterpret_cast<const char*>(fileData.constData()),
                    qMin(fileData.size(), 4096)); // Check first 4KB for markers
                
                for (const auto &marker : CANARY_MARKERS) {
                    if (fileString.contains(marker)) {
                        // Extract the section around the marker to get the token ID
                        const int markerPos = fileString.indexOf(marker);
                        if (markerPos != -1) {
                            // Get a window around the marker to find the token ID
                            const int windowStart = qMax(0, markerPos - 50);
                            const int windowEnd = qMin(fileString.length(), markerPos + marker.length() + 50);
                            const auto window = fileString.mid(windowStart, windowEnd - windowStart);
                            
                            // Check if this window contains our token ID
                            if (window.contains(token.id)) {
                                return true;
                            }
                            
                            // Check if token placement context includes this window
                            if (token.placementContext.contains(window)) {
                                return true;
                            }
                        }
                    }
                }
            }
            
            // 5. Advanced: content hash matching
            if (document->size < (1024 * 1024) && document->loaded()) {
                // For reasonably sized documents that are loaded, we
                // compute a cryptographic hash of the content and check
                // if it matches any of our registered file canaries
                
                // Full file hash
                const auto fileHash = QCryptographicHash::hash(
                    QByteArray::fromRawData(
                        reinterpret_cast<const char*>(document->data().constData()),
                        document->size),
                    QCryptographicHash::Sha256).toHex();
                
                if (token.placementContext.contains(fileHash)) {
                    return true;
                }
                
                // Partial hash of the first 4KB
                // This is useful for large files where only the header was modified
                if (document->size > 4096) {
                    const auto partialHash = QCryptographicHash::hash(
                        QByteArray::fromRawData(
                            reinterpret_cast<const char*>(document->data().constData()),
                            4096),
                        QCryptographicHash::Sha256).toHex();
                    
                    if (token.placementContext.contains(partialHash)) {
                        return true;
                    }
                }
            }
        }
    }
    return false;
}

// Honeypot data methods

HoneypotData CounterIntelligenceManager::createHoneypotData(
    HoneypotData::DataType type,
    const QString &description,
    const QVariantMap &content,
    PeerId placementPeerId) {
    
    HoneypotData data;
    data.id = HoneypotData::generateDataId();
    data.type = type;
    data.description = description;
    data.created = QDateTime::currentDateTime();
    data.content = content;
    data.fingerprint = HoneypotData::generateFingerprint(content);
    data.placementPeerId = placementPeerId;
    
    // Store the honeypot data
    _honeypotData[data.id] = data;
    
    // Save state
    saveState();
    
    return data;
}

void CounterIntelligenceManager::placeHoneypotData(
    const QString &dataId,
    PeerId placementPeerId,
    MsgId placementMsgId) {
    
    if (!_honeypotData.contains(dataId)) {
        return;
    }
    
    auto &data = _honeypotData[dataId];
    data.placementPeerId = placementPeerId;
    data.placementMsgId = placementMsgId;
    
    // Save state
    saveState();
}

void CounterIntelligenceManager::deleteHoneypotData(const QString &dataId) {
    if (_honeypotData.contains(dataId)) {
        _honeypotData.remove(dataId);
        saveState();
    }
}

HoneypotData CounterIntelligenceManager::getHoneypotData(const QString &dataId) const {
    return _honeypotData.value(dataId);
}

QVector<HoneypotData> CounterIntelligenceManager::getAllHoneypotData() const {
    QVector<HoneypotData> result;
    for (const auto &data : _honeypotData) {
        result.append(data);
    }
    return result;
}

void CounterIntelligenceManager::logHoneypotAccess(const QString &dataId, UserId accessedBy) {
    if (!_honeypotData.contains(dataId)) {
        return;
    }
    
    auto &data = _honeypotData[dataId];
    data.accessLog.append(qMakePair(accessedBy, QDateTime::currentDateTime()));
    
    // Fire the event
    _honeypotAccessedStream.fire_copy(qMakePair(data, accessedBy));
    
    // Check if this access should trigger adversary analysis
    analyzeHoneypotAccess();
    
    // Save state
    saveState();
}

rpl::producer<QPair<HoneypotData, UserId>> CounterIntelligenceManager::honeypotDataAccessed() const {
    return _honeypotAccessedStream.events();
}

void CounterIntelligenceManager::analyzeHoneypotAccess() {
    // This method analyzes patterns of honeypot access to detect
    // targeted intelligence collection and attribute it to potential adversaries
    
    // Build a map of users and their honeypot access patterns
    QMap<UserId, QVector<QPair<QString, QDateTime>>> userAccessMap;
    QMap<UserId, QSet<HoneypotData::DataType>> accessedTypes;
    QMap<UserId, int> accessCounts;
    
    // First pass: collect all honeypot access data by user
    for (const auto &data : _honeypotData) {
        for (const auto &access : data.accessLog) {
            const UserId userId = access.first;
            const QDateTime timestamp = access.second;
            
            // Skip if user ID is invalid
            if (!userId) continue;
            
            // Record this access
            userAccessMap[userId].append(qMakePair(data.id, timestamp));
            accessedTypes[userId].insert(data.type);
            accessCounts[userId]++;
        }
    }
    
    // Second pass: analyze each user's access patterns
    for (auto it = userAccessMap.begin(); it != userAccessMap.end(); ++it) {
        const UserId userId = it.key();
        const auto &accesses = it.value();
        
        // Skip if under threshold
        if (accesses.size() < _collectionThreshold) {
            continue;
        }
        
        // Calculate time span of access
        QDateTime firstAccess = QDateTime::currentDateTime();
        QDateTime lastAccess;
        
        for (const auto &access : accesses) {
            const QDateTime timestamp = access.second;
            if (timestamp < firstAccess) {
                firstAccess = timestamp;
            }
            if (timestamp > lastAccess) {
                lastAccess = timestamp;
            }
        }
        
        // Calculate time span in hours
        const int timeSpanHours = firstAccess.secsTo(lastAccess) / 3600;
        
        // Calculate access rate (accesses per hour)
        const double accessRate = timeSpanHours > 0 
            ? accesses.size() / static_cast<double>(timeSpanHours) 
            : accesses.size(); // All at once
        
        // Calculate diversity of honeypot types accessed
        const int diversityScore = accessedTypes[userId].size();
        
        // Skip users with only a single access in a short timeframe
        // that might just be exploratory/accidental
        if (accesses.size() <= 2 && timeSpanHours < 1 && diversityScore == 1) {
            continue;
        }
        
        // SUSPICIOUS PATTERNS DETECTION
        
        // 1. Rapid sequential access to multiple honeypots
        bool rapidSequentialAccess = false;
        if (accesses.size() >= 3 && timeSpanHours < 1) {
            rapidSequentialAccess = true;
        }
        
        // 2. Systematic access to all honeypots of a specific type
        bool systematicTypeAccess = false;
        for (auto typeIt = accessedTypes.begin(); typeIt != accessedTypes.end(); ++typeIt) {
            // Count total honeypots of this type
            int totalOfType = 0;
            int accessedOfType = 0;
            
            for (const auto &data : _honeypotData) {
                if (data.type == *typeIt.value().begin()) {
                    totalOfType++;
                    
                    // Check if this user accessed it
                    for (const auto &access : data.accessLog) {
                        if (access.first == userId) {
                            accessedOfType++;
                            break;
                        }
                    }
                }
            }
            
            // If user accessed more than 70% of honeypots of a specific type
            if (totalOfType > 0 && accessedOfType > 0 && 
                (static_cast<double>(accessedOfType) / totalOfType) > 0.7) {
                systematicTypeAccess = true;
                break;
            }
        }
        
        // 3. Access to honeypots with high attractiveness scores
        bool highValueTargeting = false;
        int highValueCount = 0;
        
        for (const auto &dataId : userAccessMap[userId]) {
            if (_honeypotData.contains(dataId.first) && 
                _honeypotData[dataId.first].attractivenessScore >= 8) {
                highValueCount++;
            }
        }
        
        if (highValueCount >= 2) {
            highValueTargeting = true;
        }
        
        // If we detect suspicious patterns, create or update an adversary
        if (rapidSequentialAccess || systematicTypeAccess || highValueTargeting || 
            accessCounts[userId] >= _collectionThreshold * 2) {
            
            // Check if this is a known adversary
            AttributedAdversary existingAdversary;
            bool foundExisting = false;
            
            for (const auto &adversary : _adversaries) {
                if (adversary.associatedUserIds.contains(userId)) {
                    existingAdversary = adversary;
                    foundExisting = true;
                    break;
                }
            }
            
            // Create observed tactics list
            QStringList observedTactics;
            if (rapidSequentialAccess) {
                observedTactics.append("Rapid collection");
            }
            if (systematicTypeAccess) {
                observedTactics.append("Systematic collection");
            }
            if (highValueTargeting) {
                observedTactics.append("High-value targeting");
            }
            if (accessRate > 10) {
                observedTactics.append("Automated collection");
            }
            
            // Determine data types of interest
            QStringList topicsOfInterest;
            QMap<QString, int> topicCount;
            
            for (const auto &access : accesses) {
                if (_honeypotData.contains(access.first)) {
                    const auto &data = _honeypotData[access.first];
                    
                    // Extract topics based on data type
                    if (data.type == HoneypotData::DataType::Contact) {
                        topicCount["Contacts"] = topicCount.value("Contacts", 0) + 1;
                    } else if (data.type == HoneypotData::DataType::Document) {
                        topicCount["Documents"] = topicCount.value("Documents", 0) + 1;
                        
                        // Check document content type
                        if (data.content.contains("content_type")) {
                            const auto contentType = data.content["content_type"].toString();
                            topicCount[contentType] = topicCount.value(contentType, 0) + 1;
                        }
                    } else if (data.type == HoneypotData::DataType::Message) {
                        topicCount["Messages"] = topicCount.value("Messages", 0) + 1;
                        
                        // Check message category
                        if (data.content.contains("category")) {
                            const auto category = data.content["category"].toString();
                            topicCount[category] = topicCount.value(category, 0) + 1;
                        }
                    } else if (data.type == HoneypotData::DataType::Account) {
                        topicCount["Accounts"] = topicCount.value("Accounts", 0) + 1;
                    } else if (data.type == HoneypotData::DataType::Location) {
                        topicCount["Locations"] = topicCount.value("Locations", 0) + 1;
                    }
                }
            }
            
            // Get top 3 topics of interest
            QMultiMap<int, QString> sortedTopics;
            for (auto it = topicCount.begin(); it != topicCount.end(); ++it) {
                sortedTopics.insert(it.value(), it.key());
            }
            
            auto keys = sortedTopics.keys();
            std::sort(keys.begin(), keys.end(), std::greater<int>());
            
            for (int i = 0; i < qMin(3, keys.size()); i++) {
                const auto values = sortedTopics.values(keys[i]);
                for (const auto &value : values) {
                    topicsOfInterest.append(value);
                }
            }
            
            if (foundExisting) {
                // Update existing adversary
                auto &adversary = _adversaries[existingAdversary.id];
                
                // Update last active time
                adversary.lastActive = QDateTime::currentDateTime();
                
                // Add any new tactics observed
                for (const auto &tactic : observedTactics) {
                    if (!adversary.observedTactics.contains(tactic)) {
                        adversary.observedTactics.append(tactic);
                    }
                }
                
                // Add any new topics of interest
                for (const auto &topic : topicsOfInterest) {
                    if (!adversary.topicsOfInterest.contains(topic)) {
                        adversary.topicsOfInterest.append(topic);
                    }
                }
                
                // Add a confidence factor for this new activity pattern
                AttributedAdversary::ConfidenceFactor factor;
                factor.factor = "Honeypot Access Pattern";
                factor.weight = qMin(5, accesses.size());  // Max weight of 5
                
                QString explanation = "Accessed ";
                explanation += QString::number(accesses.size());
                explanation += " honeypot items";
                
                if (!observedTactics.isEmpty()) {
                    explanation += " using " + observedTactics.join(", ");
                }
                
                factor.explanation = explanation;
                adversary.confidenceFactors.append(factor);
                
                // Recalculate confidence score
                adversary.recalculateConfidenceScore();
                
                // Save state
                saveState();
            } else if (_autoAttributionEnabled) {
                // Create a new adversary
                // Try to get the user's display name for better attribution
                QString adversaryName = "Unknown Actor #" + QString::number(qHash(userId.value) % 1000);
                
                // Create the adversary
                QStringList indicators;
                
                // Create the adversary profile
                auto adversary = createAdversary(adversaryName, indicators);
                
                // Add the user ID
                adversary.associatedUserIds.insert(userId);
                
                // Add observed tactics
                adversary.observedTactics = observedTactics;
                
                // Add topics of interest
                adversary.topicsOfInterest = topicsOfInterest;
                
                // Add a confidence factor for the honeypot access pattern
                AttributedAdversary::ConfidenceFactor factor;
                factor.factor = "Honeypot Access Pattern";
                factor.weight = qMin(5, accesses.size());  // Max weight of 5
                
                QString explanation = "Accessed ";
                explanation += QString::number(accesses.size());
                explanation += " honeypot items";
                
                if (!observedTactics.isEmpty()) {
                    explanation += " using " + observedTactics.join(", ");
                }
                
                factor.explanation = explanation;
                adversary.confidenceFactors.append(factor);
                
                // Recalculate confidence score
                adversary.recalculateConfidenceScore();
                
                // Save the updated adversary
                _adversaries[adversary.id] = adversary;
                
                // Save state
                saveState();
                
                // Fire the event
                _newAttributionStream.fire_copy(adversary);
            }
        }
    }
    
    // After analyzing individual users, try to correlate adversaries
    if (_autoAttributionEnabled && !_adversaries.isEmpty()) {
        correlateAdversaries();
        updateTacticsAttribution();
    }
}

// Generate believable honeypot data

QVariantMap CounterIntelligenceManager::generateHoneypotContact() const {
    QVariantMap contact;
    
    // Generate fake but believable contact information
    // These would ideally be randomized but plausible values
    contact["name"] = "Michael Anderson";
    contact["phone"] = "+1 (555) 123-4567";
    contact["email"] = "m.anderson@acme-corp.example.com";
    contact["position"] = "Development Lead";
    contact["company"] = "ACME Corporation";
    contact["notes"] = "Contact for Project Phoenix integration";
    
    return contact;
}

QVariantMap CounterIntelligenceManager::generateHoneypotDocument(const QString &documentType) const {
    QVariantMap document;
    
    if (documentType.toLower() == "spreadsheet") {
        document["title"] = "Q3 2023 Development Plan";
        document["author"] = "Karen Liu";
        document["created"] = "2023-06-15";
        document["department"] = "Product Development";
        document["content_type"] = "Financial Projections";
    } else if (documentType.toLower() == "presentation") {
        document["title"] = "New Product Roadmap 2024";
        document["author"] = "David Mercer";
        document["created"] = "2023-09-01";
        document["department"] = "Product Strategy";
        document["content_type"] = "Strategic Planning";
    } else {
        // Default document
        document["title"] = "Technical Specifications v2.1";
        document["author"] = "Engineering Team";
        document["created"] = "2023-08-10";
        document["department"] = "Engineering";
        document["content_type"] = "Technical Documentation";
    }
    
    return document;
}

QVariantMap CounterIntelligenceManager::generateHoneypotMessage(const QString &topic) const {
    QVariantMap message;
    
    if (topic.toLower().contains("financial")) {
        message["content"] = "Please review the updated financial projections for Q4. We need to finalize the numbers before the board meeting next Thursday.";
        message["sensitivity"] = "High";
        message["category"] = "Financial Planning";
    } else if (topic.toLower().contains("security")) {
        message["content"] = "We've updated the security protocols for remote access. Please implement the new authentication scheme before end of month.";
        message["sensitivity"] = "High";
        message["category"] = "Security Protocols";
    } else {
        // Default topic
        message["content"] = "The development team has completed the first phase of Project Aurora. Initial testing shows promising results, especially in the performance metrics.";
        message["sensitivity"] = "Medium";
        message["category"] = "Project Updates";
    }
    
    return message;
}

QVariantMap CounterIntelligenceManager::generateHoneypotAccount() const {
    QVariantMap account;
    
    // Generate fake but believable account information
    account["username"] = "j.roberts";
    account["email"] = "j.roberts@internal-systems.example.com";
    account["role"] = "Senior Developer";
    account["department"] = "Backend Services";
    account["access_level"] = "B3";
    account["joined"] = "2021-03-15";
    
    return account;
}

QVariantMap CounterIntelligenceManager::generateHoneypotLocation() const {
    QVariantMap location;

    // Generate fake but believable location data
    location["facility"] = "R&D Center East";
    location["address"] = "4200 Innovation Drive";
    location["city"] = "Boston";
    location["state"] = "MA";
    location["coordinates"] = "42.3601° N, 71.0589° W";
    location["security_level"] = "Restricted Access";

    return location;
}

QVariantMap CounterIntelligenceManager::generateHoneypotLocationWithContext(const QString &context) const {
    // If location randomization manager is available, use enhanced generation
    if (_locationRandomizationManager) {
        return _locationRandomizationManager->generateEnhancedHoneypotLocation(context);
    }

    // Fallback to basic honeypot location
    return generateHoneypotLocation();
}

void CounterIntelligenceManager::setLocationRandomizationManager(LocationRandomizationManager *lrm) {
    _locationRandomizationManager = lrm;
}

// Adversary attribution methods

AttributedAdversary CounterIntelligenceManager::createAdversary(
    const QString &name,
    const QStringList &indicators) {
    
    AttributedAdversary adversary;
    adversary.id = AttributedAdversary::generateAdversaryId();
    adversary.name = name;
    adversary.firstObserved = QDateTime::currentDateTime();
    adversary.lastActive = QDateTime::currentDateTime();
    
    // Add initial technical indicators
    for (const auto &indicator : indicators) {
        if (indicator.contains(".") && indicator.count(".") == 3) {
            // Looks like an IP address
            adversary.ipAddresses.append(indicator);
        } else if (indicator.length() >= 32) {
            // Might be a fingerprint/hash
            adversary.deviceFingerprints.append(indicator);
        }
    }
    
    // Add a default confidence factor
    AttributedAdversary::ConfidenceFactor factor;
    factor.factor = "Initial Detection";
    factor.weight = 1;
    factor.explanation = "Initial adversary profile created based on honeypot access";
    adversary.confidenceFactors.append(factor);
    
    // Calculate initial confidence score
    adversary.recalculateConfidenceScore();
    
    // Store the adversary
    _adversaries[adversary.id] = adversary;
    
    // Save state
    saveState();
    
    // Fire the event
    _newAttributionStream.fire_copy(adversary);
    
    return adversary;
}

void CounterIntelligenceManager::updateAdversaryActivity(
    const QString &adversaryId,
    UserId userId,
    const QString &ipAddress) {
    
    if (!_adversaries.contains(adversaryId)) {
        return;
    }
    
    auto &adversary = _adversaries[adversaryId];
    
    // Update last active timestamp
    adversary.lastActive = QDateTime::currentDateTime();
    
    // Add user ID if provided
    if (userId) {
        adversary.associatedUserIds.insert(userId);
    }
    
    // Add IP address if provided
    if (!ipAddress.isEmpty() && !adversary.ipAddresses.contains(ipAddress)) {
        adversary.ipAddresses.append(ipAddress);
    }
    
    // Update activity time pattern
    const auto currentHour = QTime::currentTime().toString("HH:00");
    adversary.activityTimes[currentHour] = adversary.activityTimes.value(currentHour, 0) + 1;
    
    // Save state
    saveState();
}

void CounterIntelligenceManager::deleteAdversary(const QString &adversaryId) {
    if (_adversaries.contains(adversaryId)) {
        _adversaries.remove(adversaryId);
        saveState();
    }
}

AttributedAdversary CounterIntelligenceManager::getAdversary(const QString &adversaryId) const {
    return _adversaries.value(adversaryId);
}

QVector<AttributedAdversary> CounterIntelligenceManager::getAllAdversaries() const {
    QVector<AttributedAdversary> result;
    for (const auto &adversary : _adversaries) {
        result.append(adversary);
    }
    return result;
}

QPair<AttributedAdversary, int> CounterIntelligenceManager::attributeAction(
    UserId userId,
    const QString &ipAddress,
    const QString &deviceFingerprint) {
    
    // Find the most likely adversary that matches these indicators
    AttributedAdversary bestMatch;
    int bestScore = 0;
    
    for (const auto &adversary : _adversaries) {
        int score = 0;
        
        // Check for matching user ID
        if (adversary.associatedUserIds.contains(userId)) {
            score += 3;
        }
        
        // Check for matching IP address
        if (adversary.ipAddresses.contains(ipAddress)) {
            score += 2;
        }
        
        // Check for matching device fingerprint
        if (adversary.deviceFingerprints.contains(deviceFingerprint)) {
            score += 3;
        }
        
        // Check if this activity fits the adversary's time pattern
        const auto currentHour = QTime::currentTime().toString("HH:00");
        if (adversary.activityTimes.contains(currentHour) && 
            adversary.activityTimes[currentHour] > 0) {
            score += 1;
        }
        
        // If this is a better match than what we've found so far
        if (score > bestScore) {
            bestMatch = adversary;
            bestScore = score;
        }
    }
    
    // If we found a match and auto-attribution is enabled
    if (bestScore > 0 && _autoAttributionEnabled) {
        // Update the adversary's activity
        updateAdversaryActivity(bestMatch.id, userId, ipAddress);
        
        // If the fingerprint is new, add it
        if (!deviceFingerprint.isEmpty() && 
            !bestMatch.deviceFingerprints.contains(deviceFingerprint)) {
            auto &adversary = _adversaries[bestMatch.id];
            adversary.deviceFingerprints.append(deviceFingerprint);
            saveState();
        }
    }
    
    return qMakePair(bestMatch, bestScore);
}

rpl::producer<AttributedAdversary> CounterIntelligenceManager::newAttributionMade() const {
    return _newAttributionStream.events();
}

void CounterIntelligenceManager::correlateAdversaries() {
    // This method detects similarities between different adversary profiles
    // to identify when multiple profiles likely represent the same actor
    
    // We'll use a threshold-based approach to determine correlation
    const int similarityThreshold = 70; // Percentage similarity required to correlate
    
    // Get all adversaries
    const auto allAdversaries = getAllAdversaries();
    
    // Track which adversaries have been processed to avoid duplicate work
    QSet<QString> processedAdversaries;
    
    // For each pair of adversaries, check correlation
    for (int i = 0; i < allAdversaries.size(); i++) {
        const auto &a = allAdversaries[i];
        
        // Skip if already processed
        if (processedAdversaries.contains(a.id)) {
            continue;
        }
        
        // For each potential match
        for (int j = i + 1; j < allAdversaries.size(); j++) {
            const auto &b = allAdversaries[j];
            
            // Skip if already processed
            if (processedAdversaries.contains(b.id)) {
                continue;
            }
            
            // Calculate similarity between these two adversaries
            const int similarity = calculateAdversarySimilarity(a, b);
            
            // If similarity exceeds threshold, merge adversaries
            if (similarity >= similarityThreshold) {
                // Create merged adversary
                AttributedAdversary merged;
                
                // Use information from the higher-confidence adversary as base
                if (a.confidenceScore >= b.confidenceScore) {
                    merged = a;
                } else {
                    merged = b;
                }
                
                // Generate a new ID for the merged adversary
                merged.id = AttributedAdversary::generateAdversaryId();
                
                // Combine names if they differ
                if (a.name != b.name) {
                    merged.name = a.name + " / " + b.name;
                }
                
                // Take the earliest first observed time
                merged.firstObserved = a.firstObserved < b.firstObserved ? 
                    a.firstObserved : b.firstObserved;
                
                // Take the latest last active time
                merged.lastActive = a.lastActive > b.lastActive ? 
                    a.lastActive : b.lastActive;
                
                // Combine technical indicators
                // IP addresses
                QSet<QString> ipAddresses;
                ipAddresses.unite(QSet<QString>(a.ipAddresses.begin(), a.ipAddresses.end()));
                ipAddresses.unite(QSet<QString>(b.ipAddresses.begin(), b.ipAddresses.end()));
                merged.ipAddresses = ipAddresses.values();
                
                // Device fingerprints
                QSet<QString> deviceFingerprints;
                deviceFingerprints.unite(QSet<QString>(a.deviceFingerprints.begin(), a.deviceFingerprints.end()));
                deviceFingerprints.unite(QSet<QString>(b.deviceFingerprints.begin(), b.deviceFingerprints.end()));
                merged.deviceFingerprints = deviceFingerprints.values();
                
                // User IDs
                merged.associatedUserIds.unite(a.associatedUserIds);
                merged.associatedUserIds.unite(b.associatedUserIds);
                
                // Combine behavioral patterns
                // Activity times
                QMap<QString, int> activityTimes = a.activityTimes;
                for (auto it = b.activityTimes.begin(); it != b.activityTimes.end(); ++it) {
                    activityTimes[it.key()] = activityTimes.value(it.key(), 0) + it.value();
                }
                merged.activityTimes = activityTimes;
                
                // Language patterns
                QMap<QString, int> languagePatterns = a.languagePatterns;
                for (auto it = b.languagePatterns.begin(); it != b.languagePatterns.end(); ++it) {
                    languagePatterns[it.key()] = languagePatterns.value(it.key(), 0) + it.value();
                }
                merged.languagePatterns = languagePatterns;
                
                // Topics of interest
                QSet<QString> topicsOfInterest;
                topicsOfInterest.unite(QSet<QString>(a.topicsOfInterest.begin(), a.topicsOfInterest.end()));
                topicsOfInterest.unite(QSet<QString>(b.topicsOfInterest.begin(), b.topicsOfInterest.end()));
                merged.topicsOfInterest = topicsOfInterest.values();
                
                // Combine confidence factors
                merged.confidenceFactors = a.confidenceFactors;
                for (const auto &factor : b.confidenceFactors) {
                    // Avoid duplicate factors
                    bool factorExists = false;
                    for (const auto &existingFactor : merged.confidenceFactors) {
                        if (existingFactor.factor == factor.factor) {
                            factorExists = true;
                            break;
                        }
                    }
                    
                    if (!factorExists) {
                        merged.confidenceFactors.append(factor);
                    }
                }
                
                // Add a new confidence factor for the correlation
                AttributedAdversary::ConfidenceFactor correlationFactor;
                correlationFactor.factor = "Profile Correlation";
                correlationFactor.weight = 3;
                correlationFactor.explanation = QString("Merged from profiles %1 and %2 with %3% similarity")
                    .arg(a.id.left(8), b.id.left(8), QString::number(similarity));
                merged.confidenceFactors.append(correlationFactor);
                
                // Combine observed tactics
                QSet<QString> observedTactics;
                observedTactics.unite(QSet<QString>(a.observedTactics.begin(), a.observedTactics.end()));
                observedTactics.unite(QSet<QString>(b.observedTactics.begin(), b.observedTactics.end()));
                merged.observedTactics = observedTactics.values();
                
                // Recalculate confidence score
                merged.recalculateConfidenceScore();
                
                // Add the merged adversary to our collection
                _adversaries[merged.id] = merged;
                
                // Remove the original adversaries
                _adversaries.remove(a.id);
                _adversaries.remove(b.id);
                
                // Mark these as processed
                processedAdversaries.insert(a.id);
                processedAdversaries.insert(b.id);
                
                // If the original adversaries were in groups, handle group membership
                if (!a.groupId.isEmpty() && !b.groupId.isEmpty()) {
                    if (a.groupId == b.groupId) {
                        // If they were in the same group, add the merged adversary to that group
                        merged.groupId = a.groupId;
                        
                        // Update the group's member list if it exists
                        if (_adversaryGroups.contains(a.groupId)) {
                            auto &group = _adversaryGroups[a.groupId];
                            group.memberIds.removeAll(a.id);
                            group.memberIds.removeAll(b.id);
                            group.memberIds.append(merged.id);
                            
                            // Recalculate group cohesion
                            group.recalculateCohesionScore();
                        }
                    } else {
                        // If they were in different groups, this might suggest merging the groups
                        // For now, we'll put the merged adversary in the group with higher cohesion
                        if (_adversaryGroups.contains(a.groupId) && _adversaryGroups.contains(b.groupId)) {
                            if (_adversaryGroups[a.groupId].cohesionScore >= _adversaryGroups[b.groupId].cohesionScore) {
                                merged.groupId = a.groupId;
                                
                                // Update group member lists
                                auto &groupA = _adversaryGroups[a.groupId];
                                auto &groupB = _adversaryGroups[b.groupId];
                                
                                groupA.memberIds.removeAll(a.id);
                                groupB.memberIds.removeAll(b.id);
                                groupA.memberIds.append(merged.id);
                                
                                // Recalculate group cohesion
                                groupA.recalculateCohesionScore();
                                groupB.recalculateCohesionScore();
                                
                                // Strengthen the relationship between these groups
                                const int currentRelation = groupA.relationToGroups.value(b.groupId, 0);
                                groupA.relationToGroups[b.groupId] = qMax(currentRelation, similarity);
                                groupB.relationToGroups[a.groupId] = qMax(currentRelation, similarity);
                            } else {
                                merged.groupId = b.groupId;
                                
                                // Update group member lists
                                auto &groupA = _adversaryGroups[a.groupId];
                                auto &groupB = _adversaryGroups[b.groupId];
                                
                                groupA.memberIds.removeAll(a.id);
                                groupB.memberIds.removeAll(b.id);
                                groupB.memberIds.append(merged.id);
                                
                                // Recalculate group cohesion
                                groupA.recalculateCohesionScore();
                                groupB.recalculateCohesionScore();
                                
                                // Strengthen the relationship between these groups
                                const int currentRelation = groupA.relationToGroups.value(b.groupId, 0);
                                groupA.relationToGroups[b.groupId] = qMax(currentRelation, similarity);
                                groupB.relationToGroups[a.groupId] = qMax(currentRelation, similarity);
                            }
                        }
                    }
                } else if (!a.groupId.isEmpty()) {
                    // Only 'a' was in a group, add merged to that group
                    merged.groupId = a.groupId;
                    
                    // Update the group's member list
                    if (_adversaryGroups.contains(a.groupId)) {
                        auto &group = _adversaryGroups[a.groupId];
                        group.memberIds.removeAll(a.id);
                        group.memberIds.append(merged.id);
                        
                        // Recalculate group cohesion
                        group.recalculateCohesionScore();
                    }
                } else if (!b.groupId.isEmpty()) {
                    // Only 'b' was in a group, add merged to that group
                    merged.groupId = b.groupId;
                    
                    // Update the group's member list
                    if (_adversaryGroups.contains(b.groupId)) {
                        auto &group = _adversaryGroups[b.groupId];
                        group.memberIds.removeAll(b.id);
                        group.memberIds.append(merged.id);
                        
                        // Recalculate group cohesion
                        group.recalculateCohesionScore();
                    }
                }
                
                // Save state
                saveState();
                
                // Fire the event for the new adversary
                _newAttributionStream.fire_copy(merged);
                
                // Break inner loop and continue with next i
                break;
            }
        }
    }
    
    // Update group relationships
    updateGroupRelationships();
}

void CounterIntelligenceManager::updateTacticsAttribution() {
    // This method analyzes patterns across all adversaries to identify
    // and categorize their tactics, techniques, and procedures (TTPs)
    
    // Define known TTP categories based on common intelligence collection methods
    const QMap<QString, QStringList> ttpPatterns = {
        // Reconnaissance tactics
        {"Reconnaissance", {
            "Profile scanning", "Contact enumeration", "Account probing",
            "Relationship mapping", "Information gathering", "Channel scanning"
        }},
        
        // Collection tactics
        {"Collection", {
            "Rapid collection", "Systematic collection", "High-value targeting",
            "Automated collection", "Bulk extraction", "Data harvesting",
            "Selective targeting"
        }},
        
        // Exfiltration tactics
        {"Exfiltration", {
            "Document downloading", "Media extraction", "Screenshot capture",
            "Text copying", "Contact harvesting", "Location data collection"
        }},
        
        // Technical tactics
        {"Technical", {
            "API scraping", "Automation", "Multi-device access", "VPN rotation",
            "Proxy usage", "Tor access", "Browser fingerprint manipulation"
        }},
        
        // Social engineering
        {"Social Engineering", {
            "Impersonation", "Trust building", "Pretexting", "Authority invocation",
            "Relationship exploitation", "Group infiltration", "Channel monitoring"
        }}
    };
    
    // Define social engineering keyword patterns for conversation analysis
    const QMap<QString, QStringList> socialEngineeringPatterns = {
        {"Urgency", {
            "urgent", "immediately", "right now", "asap", "emergency", "deadline",
            "quickly", "hurry", "fast", "now", "instant", "promptly"
        }},
        
        {"Authority", {
            "admin", "administrator", "management", "executive", "official", "director",
            "supervisor", "boss", "manager", "ceo", "leadership", "head of"
        }},
        
        {"Fear", {
            "warning", "alert", "threat", "risk", "danger", "vulnerable", "compromise",
            "breach", "attack", "hack", "malware", "virus", "stolen", "exposed"
        }},
        
        {"Curiosity", {
            "exclusive", "secret", "confidential", "private", "sensitive", "classified",
            "restricted", "limited", "special access", "insider", "unknown"
        }},
        
        {"Trust", {
            "verify", "authenticate", "confirm", "validate", "approve", "authorize",
            "trusted", "secure", "protected", "safe", "reliable", "legitimate"
        }},
        
        {"Financial", {
            "money", "payment", "fund", "transfer", "account", "bank", "transaction",
            "wallet", "crypto", "bitcoin", "investment", "financial", "payment"
        }},
        
        {"Credential", {
            "login", "password", "credential", "username", "account", "authenticate",
            "verify", "code", "pin", "token", "access", "two-factor", "2fa"
        }}
    };
    
    // For each adversary, analyze their behaviors to identify TTPs
    for (auto it = _adversaries.begin(); it != _adversaries.end(); ++it) {
        auto &adversary = it.value();
        
        // Skip if this adversary already has comprehensive tactics identified
        if (adversary.observedTactics.size() >= 5) {
            continue;
        }
        
        // Collect evidence for different TTPs
        QMap<QString, int> ttpEvidence;
        
        // Check existing tactics first
        for (const auto &tactic : adversary.observedTactics) {
            // Map this tactic to its category
            for (auto catIt = ttpPatterns.begin(); catIt != ttpPatterns.end(); ++catIt) {
                if (catIt.value().contains(tactic, Qt::CaseInsensitive)) {
                    ttpEvidence[catIt.key()] = ttpEvidence.value(catIt.key(), 0) + 2;
                    break;
                }
            }
        }
        
        // Analyze access patterns from honeypot data
        for (const auto &data : _honeypotData) {
            for (const auto &access : data.accessLog) {
                // Check if this user accessed this honeypot
                if (adversary.associatedUserIds.contains(access.first)) {
                    // Evidence for Collection
                    ttpEvidence["Collection"] = ttpEvidence.value("Collection", 0) + 1;
                    
                    // Determine data type for more specific categorization
                    if (data.type == HoneypotData::DataType::Contact) {
                        ttpEvidence["Reconnaissance"] = ttpEvidence.value("Reconnaissance", 0) + 1;
                    } else if (data.type == HoneypotData::DataType::Document) {
                        ttpEvidence["Exfiltration"] = ttpEvidence.value("Exfiltration", 0) + 1;
                    } else if (data.type == HoneypotData::DataType::Account) {
                        ttpEvidence["Technical"] = ttpEvidence.value("Technical", 0) + 1;
                    }
                    
                    // Check attractiveness score for targeted collection
                    if (data.attractivenessScore >= 8) {
                        ttpEvidence["Collection"] = ttpEvidence.value("Collection", 0) + 1;
                    }
                }
            }
        }
        
        // Check technical indicators
        if (adversary.ipAddresses.size() > 3) {
            ttpEvidence["Technical"] = ttpEvidence.value("Technical", 0) + 2;
        }
        
        if (adversary.deviceFingerprints.size() > 2) {
            ttpEvidence["Technical"] = ttpEvidence.value("Technical", 0) + 2;
        }
        
        // Analyze activity times for automated behavior
        if (adversary.activityTimes.size() > 12) { // Active across many different hours
            ttpEvidence["Technical"] = ttpEvidence.value("Technical", 0) + 1;
        }
        
        // Check if most activity happens during normal business hours
        int businessHourActivity = 0;
        int nonBusinessHourActivity = 0;
        for (auto it = adversary.activityTimes.begin(); it != adversary.activityTimes.end(); ++it) {
            const auto hour = it.key().split(":").first().toInt();
            if (hour >= 9 && hour <= 17) {
                businessHourActivity += it.value();
            } else {
                nonBusinessHourActivity += it.value();
            }
        }
        
        if (businessHourActivity > nonBusinessHourActivity * 2) {
            // Strong bias toward business hours suggests professional/organized activity
            ttpEvidence["Technical"] = ttpEvidence.value("Technical", 0) + 1;
        }
        
        // Analyze conversations for social engineering patterns
        for (const auto &userId : adversary.associatedUserIds) {
            // Get user conversations if available through the session
            if (Core::App().activeAccount().sessionExists()) {
                auto &session = Core::App().activeAccount().session();
                if (const auto user = session.data().userLoaded(userId)) {
                    // Get history with this user
                    auto history = session.data().history(user->id);
                    
                    // Check for patterns in messages
                    // Get the most recent messages (up to 100)
                    auto messages = history->getMessages(0, 100);
                    
                    // Track patterns found in conversations
                    QMap<QString, int> patternMatches;
                    
                    // Analyze message content for social engineering patterns
                    for (const auto &message : messages) {
                        // Skip service messages and non-text messages
                        if (!message || !message->isRegular() || !message->isText()) {
                            continue;
                        }
                        
                        // Skip outgoing messages (we want to analyze what the potential adversary is saying)
                        if (message->out()) {
                            continue;
                        }
                        
                        // Get the text content
                        const auto &messageText = message->originalText().text;
                        
                        // Check each pattern category
                        for (auto patternIt = socialEngineeringPatterns.begin(); 
                             patternIt != socialEngineeringPatterns.end(); ++patternIt) {
                            
                            // The category name
                            const auto &category = patternIt.key();
                            
                            // Check each keyword in this category
                            for (const auto &keyword : patternIt.value()) {
                                // Simple case-insensitive keyword matching
                                if (messageText.toLower().contains(keyword)) {
                                    patternMatches[category] = patternMatches.value(category, 0) + 1;
                                    // Only count once per keyword per message
                                    break;
                                }
                            }
                        }
                    }
                    
                    // If we found social engineering patterns
                    int totalPatterns = 0;
                    int patternCategories = 0;
                    for (auto it = patternMatches.begin(); it != patternMatches.end(); ++it) {
                        totalPatterns += it.value();
                        patternCategories++;
                    }
                    
                    // If we have multiple pattern categories and multiple matches,
                    // this is strong evidence of social engineering
                    if (patternCategories >= 2 && totalPatterns >= 4) {
                        // Add evidence for social engineering tactics
                        ttpEvidence["Social Engineering"] = ttpEvidence.value("Social Engineering", 0) + 
                            qMin(5, patternCategories + (totalPatterns / 2));
                        
                        // Determine the dominant social engineering technique
                        QString dominantTechnique;
                        int highestCount = 0;
                        
                        for (auto it = patternMatches.begin(); it != patternMatches.end(); ++it) {
                            if (it.value() > highestCount) {
                                highestCount = it.value();
                                dominantTechnique = it.key();
                            }
                        }
                        
                        // Map the dominant technique to a specific tactic
                        QString specificTactic;
                        if (dominantTechnique == "Authority") {
                            specificTactic = "Authority invocation";
                        } else if (dominantTechnique == "Fear") {
                            specificTactic = "Fear manipulation";
                        } else if (dominantTechnique == "Urgency") {
                            specificTactic = "Urgency exploitation";
                        } else if (dominantTechnique == "Trust") {
                            specificTactic = "Trust building";
                        } else if (dominantTechnique == "Credential") {
                            specificTactic = "Credential harvesting";
                        } else if (dominantTechnique == "Financial") {
                            specificTactic = "Financial manipulation";
                        } else {
                            specificTactic = "General social engineering";
                        }
                        
                        // Add this specific tactic if not already present
                        if (!adversary.observedTactics.contains(specificTactic)) {
                            adversary.observedTactics.append(specificTactic);
                        }
                    }
                }
            }
        }
        
        // For each TTP category with sufficient evidence, add to observed tactics
        for (auto ttpIt = ttpEvidence.begin(); ttpIt != ttpEvidence.end(); ++ttpIt) {
            // Threshold for considering a TTP category observed
            if (ttpIt.value() >= 3) {
                // Add the category as a high-level tactic
                if (!adversary.observedTactics.contains(ttpIt.key())) {
                    adversary.observedTactics.append(ttpIt.key());
                }
                
                // Add specific tactics from this category if we have strong evidence
                if (ttpIt.value() >= 5) {
                    // Get specific tactics from this category
                    const auto specificTactics = ttpPatterns.value(ttpIt.key());
                    
                    // Add 1-2 specific tactics based on the strength of evidence
                    const int numTacticsToAdd = qMin(2, ttpIt.value() / 5);
                    
                    for (int i = 0; i < numTacticsToAdd; i++) {
                        // Select a tactic that's not already in the list
                        for (const auto &tactic : specificTactics) {
                            if (!adversary.observedTactics.contains(tactic)) {
                                adversary.observedTactics.append(tactic);
                                break;
                            }
                        }
                    }
                }
            }
        }
        
        // If we've added new tactics, add a confidence factor for this analysis
        if (adversary.observedTactics.size() > 0) {
            // Check if we already have a TTP analysis confidence factor
            bool hasTtpFactor = false;
            for (const auto &factor : adversary.confidenceFactors) {
                if (factor.factor.contains("TTP Analysis")) {
                    hasTtpFactor = true;
                    break;
                }
            }
            
            if (!hasTtpFactor) {
                AttributedAdversary::ConfidenceFactor ttpFactor;
                ttpFactor.factor = "TTP Analysis";
                ttpFactor.weight = 2;
                ttpFactor.explanation = QString("Identified %1 tactics based on behavior analysis")
                    .arg(adversary.observedTactics.size());
                adversary.confidenceFactors.append(ttpFactor);
                
                // Recalculate confidence score
                adversary.recalculateConfidenceScore();
            }
        }
    }
    
    // Save state
    saveState();
}

// CounterIntelligenceManager Group methods

AdversaryGroup CounterIntelligenceManager::createGroup(
    const QString &name,
    const QString &description) {
    
    AdversaryGroup group;
    group.id = AdversaryGroup::generateGroupId();
    group.name = name;
    group.description = description;
    group.created = QDateTime::currentDateTime();
    group.color = AdversaryGroup::generateGroupColor(group.id);
    
    // Assign a random emoji as an identifier
    const QStringList emojiOptions = {
        "🦊", "🐺", "🦁", "🐯", "🦒", "🦓", "🦄", "🦅", "🦇", "🐙", 
        "🦂", "🦖", "🦕", "🦚", "🦜", "🦢", "🦩", "🦡", "🦦", "🦥"
    };
    group.emoji = emojiOptions[QRandomGenerator::global()->bounded(emojiOptions.size())];
    
    // Store the group
    _adversaryGroups[group.id] = group;
    
    // Save state
    saveState();
    
    // Fire the event
    _groupUpdatedStream.fire_copy(group);
    
    return group;
}

void CounterIntelligenceManager::updateGroup(const AdversaryGroup &group) {
    if (!_adversaryGroups.contains(group.id)) {
        return;
    }
    
    _adversaryGroups[group.id] = group;
    
    // Save state
    saveState();
    
    // Fire the event
    _groupUpdatedStream.fire_copy(group);
}

void CounterIntelligenceManager::deleteGroup(const QString &groupId) {
    if (!_adversaryGroups.contains(groupId)) {
        return;
    }
    
    // Remove group association from all adversaries in this group
    for (auto &adversary : _adversaries) {
        if (adversary.groupId == groupId) {
            adversary.groupId.clear();
            // Save the adversary state (this is a bit inefficient but maintains consistency)
            saveState();
        }
    }
    
    // Remove the group
    _adversaryGroups.remove(groupId);
    
    // Save state
    saveState();
}

AdversaryGroup CounterIntelligenceManager::getGroup(const QString &groupId) const {
    return _adversaryGroups.value(groupId);
}

QVector<AdversaryGroup> CounterIntelligenceManager::getAllGroups() const {
    QVector<AdversaryGroup> result;
    for (const auto &group : _adversaryGroups) {
        result.append(group);
    }
    return result;
}

void CounterIntelligenceManager::addAdversaryToGroup(
    const QString &adversaryId,
    const QString &groupId) {
    
    if (!_adversaries.contains(adversaryId) || !_adversaryGroups.contains(groupId)) {
        return;
    }
    
    // Update the adversary's group
    auto &adversary = _adversaries[adversaryId];
    adversary.groupId = groupId;
    
    // Update the group's member list
    auto &group = _adversaryGroups[groupId];
    if (!group.memberIds.contains(adversaryId)) {
        group.memberIds.append(adversaryId);
    }
    
    // Recalculate group cohesion
    group.recalculateCohesionScore();
    
    // Save state
    saveState();
    
    // Fire the group update event
    _groupUpdatedStream.fire_copy(group);
}

void CounterIntelligenceManager::removeAdversaryFromGroup(
    const QString &adversaryId,
    const QString &groupId) {
    
    if (!_adversaries.contains(adversaryId) || !_adversaryGroups.contains(groupId)) {
        return;
    }
    
    // Update the adversary's group
    auto &adversary = _adversaries[adversaryId];
    if (adversary.groupId == groupId) {
        adversary.groupId.clear();
    }
    
    // Update the group's member list
    auto &group = _adversaryGroups[groupId];
    group.memberIds.removeAll(adversaryId);
    
    // Recalculate group cohesion
    group.recalculateCohesionScore();
    
    // Save state
    saveState();
    
    // Fire the group update event
    _groupUpdatedStream.fire_copy(group);
}

void CounterIntelligenceManager::autoGroupAdversaries(int similarityThreshold) {
    // Get all adversaries and calculate similarity between them
    const auto allAdversaries = getAllAdversaries();
    
    // Track which adversaries have been grouped
    QSet<QString> groupedAdversaries;
    
    // For each pair of adversaries
    for (int i = 0; i < allAdversaries.size(); i++) {
        const auto &a = allAdversaries[i];
        
        // Skip if already grouped
        if (groupedAdversaries.contains(a.id)) {
            continue;
        }
        
        // Find similar adversaries
        QVector<QString> similarAdversaries;
        similarAdversaries.append(a.id);
        
        for (int j = i + 1; j < allAdversaries.size(); j++) {
            const auto &b = allAdversaries[j];
            
            // Skip if already grouped
            if (groupedAdversaries.contains(b.id)) {
                continue;
            }
            
            // Calculate similarity
            const int similarity = calculateAdversarySimilarity(a, b);
            
            // If similarity exceeds threshold, add to group
            if (similarity >= similarityThreshold) {
                similarAdversaries.append(b.id);
            }
        }
        
        // If we found similar adversaries, create a group
        if (similarAdversaries.size() > 1) {
            // Create a group name based on pattern detected
            QString groupName = QString("Group #%1").arg(_adversaryGroups.size() + 1);
            QString description = QString("Auto-grouped based on %1% similarity threshold").arg(similarityThreshold);
            
            // Create the group
            auto group = createGroup(groupName, description);
            
            // Add all similar adversaries to the group
            for (const auto &adversaryId : similarAdversaries) {
                addAdversaryToGroup(adversaryId, group.id);
                groupedAdversaries.insert(adversaryId);
            }
        }
    }
    
    // Update relationships between groups
    updateGroupRelationships();
    
    // Save state
    saveState();
}

int CounterIntelligenceManager::calculateAdversarySimilarity(
    const AttributedAdversary &a,
    const AttributedAdversary &b) const {
    
    int similarityScore = 0;
    int totalFactors = 0;
    
    // Check IP overlap
    QSet<QString> aIPs = QSet<QString>(a.ipAddresses.begin(), a.ipAddresses.end());
    QSet<QString> bIPs = QSet<QString>(b.ipAddresses.begin(), b.ipAddresses.end());
    int ipOverlap = aIPs.intersects(bIPs) ? 25 : 0;
    similarityScore += ipOverlap;
    totalFactors += 25;
    
    // Check device fingerprint overlap
    QSet<QString> aFingerprints = QSet<QString>(a.deviceFingerprints.begin(), a.deviceFingerprints.end());
    QSet<QString> bFingerprints = QSet<QString>(b.deviceFingerprints.begin(), b.deviceFingerprints.end());
    int fingerprintOverlap = aFingerprints.intersects(bFingerprints) ? 25 : 0;
    similarityScore += fingerprintOverlap;
    totalFactors += 25;
    
    // Check activity time pattern similarity
    int activityTimeScore = 0;
    int timeComparisonCount = 0;
    
    for (auto it = a.activityTimes.begin(); it != a.activityTimes.end(); ++it) {
        if (b.activityTimes.contains(it.key())) {
            // Compare frequency - normalized to 0-10 range
            int aTimes = qBound(0, it.value(), 10);
            int bTimes = qBound(0, b.activityTimes[it.key()], 10);
            int difference = qAbs(aTimes - bTimes);
            
            // Score is 10 for exact match, down to 0 for max difference
            int timeMatchScore = 10 - difference;
            activityTimeScore += timeMatchScore;
            timeComparisonCount++;
        }
    }
    
    // Calculate average activity time similarity if we have comparisons
    if (timeComparisonCount > 0) {
        activityTimeScore = (activityTimeScore * 25) / (timeComparisonCount * 10);
        similarityScore += activityTimeScore;
        totalFactors += 25;
    }
    
    // Check topic interest overlap
    QSet<QString> aTopics = QSet<QString>(a.topicsOfInterest.begin(), a.topicsOfInterest.end());
    QSet<QString> bTopics = QSet<QString>(b.topicsOfInterest.begin(), b.topicsOfInterest.end());
    
    int topicOverlap = 0;
    if (!aTopics.isEmpty() && !bTopics.isEmpty()) {
        QSet<QString> intersect = aTopics.intersect(bTopics);
        QSet<QString> unionSet = aTopics.unite(bTopics);
        
        if (!unionSet.isEmpty()) {
            // Jaccard similarity: intersection/union
            topicOverlap = (intersect.size() * 25) / unionSet.size();
        }
        
        similarityScore += topicOverlap;
        totalFactors += 25;
    }
    
    // Calculate final percentage
    return totalFactors > 0 ? (similarityScore * 100) / totalFactors : 0;
}

void CounterIntelligenceManager::updateGroupRelationships() {
    // For each pair of groups, calculate relationship strength
    const auto groups = getAllGroups();
    
    for (int i = 0; i < groups.size(); i++) {
        const auto &groupA = groups[i];
        
        for (int j = i + 1; j < groups.size(); j++) {
            const auto &groupB = groups[j];
            
            // Calculate relationship based on shared characteristics
            int relationStrength = 0;
            
            // Check for adversaries that share indicators but are in different groups
            for (const auto &adversaryIdA : groupA.memberIds) {
                if (!_adversaries.contains(adversaryIdA)) continue;
                const auto &adversaryA = _adversaries[adversaryIdA];
                
                for (const auto &adversaryIdB : groupB.memberIds) {
                    if (!_adversaries.contains(adversaryIdB)) continue;
                    const auto &adversaryB = _adversaries[adversaryIdB];
                    
                    // Calculate similarity between these adversaries
                    int similarity = calculateAdversarySimilarity(adversaryA, adversaryB);
                    
                    // Update relationship strength based on highest similarity found
                    relationStrength = qMax(relationStrength, similarity);
                }
            }
            
            // Only store meaningful relationships
            if (relationStrength > 20) {
                // Update both groups' relationships
                auto &groupAMutable = _adversaryGroups[groupA.id];
                auto &groupBMutable = _adversaryGroups[groupB.id];
                
                groupAMutable.relationToGroups[groupB.id] = relationStrength;
                groupBMutable.relationToGroups[groupA.id] = relationStrength;
                
                // Recalculate cohesion scores
                groupAMutable.recalculateCohesionScore();
                groupBMutable.recalculateCohesionScore();
            }
        }
    }
    
    // Save state
    saveState();
}

void CounterIntelligenceManager::mergeGroups(
    const QString &groupId1,
    const QString &groupId2) {
    
    if (!_adversaryGroups.contains(groupId1) || !_adversaryGroups.contains(groupId2)) {
        return;
    }
    
    const auto &group1 = _adversaryGroups[groupId1];
    const auto &group2 = _adversaryGroups[groupId2];
    
    // Create a new merged group name
    QString mergedName = QString("%1 + %2").arg(group1.name, group2.name);
    QString mergedDescription = QString("Merged group containing members from %1 and %2")
        .arg(group1.name, group2.name);
    
    // Create the merged group
    auto mergedGroup = createGroup(mergedName, mergedDescription);
    
    // Add all members from both groups
    QSet<QString> allMembers;
    allMembers.unite(QSet<QString>(group1.memberIds.begin(), group1.memberIds.end()));
    allMembers.unite(QSet<QString>(group2.memberIds.begin(), group2.memberIds.end()));
    
    for (const auto &memberId : allMembers) {
        addAdversaryToGroup(memberId, mergedGroup.id);
    }
    
    // Delete the original groups
    deleteGroup(groupId1);
    deleteGroup(groupId2);
    
    // Update relationships between all groups
    updateGroupRelationships();
}

QColor CounterIntelligenceManager::getUserColor(UserId userId) const {
    // Default color for users not in any group
    static const QColor defaultColor = QColor(150, 150, 150); // Gray
    
    // Find the adversary profile for this user
    for (const auto &adversary : _adversaries) {
        if (adversary.associatedUserIds.contains(userId)) {
            // If the adversary is part of a group, return the group color
            if (!adversary.groupId.isEmpty() && _adversaryGroups.contains(adversary.groupId)) {
                return _adversaryGroups[adversary.groupId].color;
            }
            
            // If we found an adversary but no group, use a color based on the adversary ID
            return QColor(
                qBound(100, static_cast<int>(qHash(adversary.id) & 0xFF), 220),
                qBound(100, static_cast<int>((qHash(adversary.id) >> 8) & 0xFF), 220),
                qBound(100, static_cast<int>((qHash(adversary.id) >> 16) & 0xFF), 220)
            );
        }
    }
    
    // No adversary found for this user
    return defaultColor;
}

QString CounterIntelligenceManager::getUserGroupEmoji(UserId userId) const {
    // Find the adversary profile for this user
    for (const auto &adversary : _adversaries) {
        if (adversary.associatedUserIds.contains(userId)) {
            // If the adversary is part of a group, return the group emoji
            if (!adversary.groupId.isEmpty() && _adversaryGroups.contains(adversary.groupId)) {
                return _adversaryGroups[adversary.groupId].emoji;
            }
            
            // If no group, return a default "adversary" emoji
            return "👤";
        }
    }
    
    // No adversary found for this user
    return QString();
}

rpl::producer<AdversaryGroup> CounterIntelligenceManager::groupUpdated() const {
    return _groupUpdatedStream.events();
}

// Advanced social engineering pattern analysis
struct ConversationMetrics {
    int messageFrequency{0};  // Messages per hour
    int responseLatency{0};   // Average time to respond in seconds
    int messageLength{0};     // Average message length
    int questionFrequency{0}; // Questions per message
    int linkFrequency{0};     // Links per message
    double emotionalIntensity{0.0}; // Measured emotional content
    QMap<QString, int> topicTransitions; // How topics change
    QVector<QPair<qint64, QString>> conversationFlow; // Message timing and content
};

void CounterIntelligenceManager::analyzeSocialEngineeringBehavior(
    const AttributedAdversary &adversary,
    QMap<QString, int> &ttpEvidence) {
    
    if (!Core::App().activeAccount().sessionExists()) {
        return;
    }
    
    auto &session = Core::App().activeAccount().session();
    
    // Track conversation patterns across all user interactions
    QMap<UserId, ConversationMetrics> userMetrics;
    
    for (const auto userId : adversary.associatedUserIds) {
        if (const auto user = session.data().userLoaded(userId)) {
            auto history = session.data().history(user->id);
            auto messages = history->getMessages(0, 200); // Analyze more messages
            
            ConversationMetrics metrics;
            QDateTime firstMsg, lastMsg;
            int totalLength = 0;
            int totalQuestions = 0;
            int totalLinks = 0;
            
            // Regular expressions for more sophisticated pattern matching
            static const QRegularExpression questionPattern(
                R"((?:^|\s)(?:who|what|when|where|why|how|could you|would you|will you|can you|do you|are you|is it|isn't it)\b.*\?)",
                QRegularExpression::CaseInsensitiveOption
            );
            
            static const QRegularExpression linkPattern(
                R"((https?://[^\s]+)|(www\.[^\s]+))",
                QRegularExpression::CaseInsensitiveOption
            );
            
            static const QRegularExpression emotionalPattern(
                R"((!{2,}|\?{2,}|\.{3,}|PLEASE|URGENT|ASAP|NOW|(?:^|\s)(?:very|really|extremely|absolutely|definitely|urgently)\s))",
                QRegularExpression::CaseInsensitiveOption
            );
            
            // Advanced manipulation pattern detection
            static const QMap<QString, QRegularExpression> manipulationPatterns = {
                {"Reciprocity", QRegularExpression(R"((?:i(?:'ve| have) done|i did|i gave|in return|favor|help.*back))", QRegularExpression::CaseInsensitiveOption)},
                {"Scarcity", QRegularExpression(R"((?:limited|only|exclusive|rare|running out|expires?|deadline|last chance))", QRegularExpression::CaseInsensitiveOption)},
                {"Authority", QRegularExpression(R"((?:supervisor|manager|admin|security|IT department|compliance|policy|required by))", QRegularExpression::CaseInsensitiveOption)},
                {"Consistency", QRegularExpression(R"((?:you (?:said|agreed|promised|mentioned)|as discussed|follow(?:ing)? up|remember))", QRegularExpression::CaseInsensitiveOption)},
                {"Social Proof", QRegularExpression(R"((?:others? have|everyone|nobody|standard practice|normal procedure|typically))", QRegularExpression::CaseInsensitiveOption)},
                {"Liking", QRegularExpression(R"((?:appreciate|thank|grateful|sorry to|hate to|please help|would mean))", QRegularExpression::CaseInsensitiveOption)}
            };
            
            QMap<QString, int> manipulationCounts;
            QString prevTopic;
            
            for (const auto &message : messages) {
                if (!message || !message->isRegular() || message->out()) {
                    continue;
                }
                
                const auto &text = message->originalText().text;
                const auto timestamp = message->date();
                
                if (firstMsg.isNull()) {
                    firstMsg = timestamp;
                }
                lastMsg = timestamp;
                
                // Track message flow
                metrics.conversationFlow.append({timestamp.toSecsSinceEpoch(), text});
                
                // Analyze message characteristics
                totalLength += text.length();
                totalQuestions += text.count(questionPattern);
                totalLinks += text.count(linkPattern);
                
                // Track emotional intensity
                metrics.emotionalIntensity += text.count(emotionalPattern) * 0.5;
                
                // Detect manipulation tactics
                for (auto it = manipulationPatterns.begin(); it != manipulationPatterns.end(); ++it) {
                    if (text.contains(it.value())) {
                        manipulationCounts[it.key()]++;
                        
                        // Topic transition analysis
                        if (!prevTopic.isEmpty() && prevTopic != it.key()) {
                            QString transition = prevTopic + "->" + it.key();
                            metrics.topicTransitions[transition]++;
                        }
                        prevTopic = it.key();
                    }
                }
            }
            
            // Calculate metrics
            if (!messages.isEmpty()) {
                const int timeSpan = firstMsg.secsTo(lastMsg) / 3600 + 1; // Hours
                metrics.messageFrequency = messages.size() / timeSpan;
                metrics.messageLength = totalLength / messages.size();
                metrics.questionFrequency = totalQuestions * 100 / messages.size();
                metrics.linkFrequency = totalLinks * 100 / messages.size();
                
                // Analyze conversation dynamics
                analyzeConversationDynamics(metrics, manipulationCounts, ttpEvidence);
            }
            
            userMetrics[userId] = metrics;
        }
    }
    
    // Cross-user pattern analysis
    if (userMetrics.size() > 1) {
        analyzeCrossUserPatterns(userMetrics, ttpEvidence);
    }
}

void CounterIntelligenceManager::analyzeConversationDynamics(
    const ConversationMetrics &metrics,
    const QMap<QString, int> &manipulationCounts,
    QMap<QString, int> &ttpEvidence) {
    
    // Score different aspects of social engineering sophistication
    int sophisticationScore = 0;
    
    // 1. Analyze manipulation tactic diversity
    int tacticsUsed = 0;
    int dominantTacticCount = 0;
    QString dominantTactic;
    
    for (auto it = manipulationCounts.begin(); it != manipulationCounts.end(); ++it) {
        if (it.value() > 0) {
            tacticsUsed++;
            if (it.value() > dominantTacticCount) {
                dominantTacticCount = it.value();
                dominantTactic = it.key();
            }
        }
    }
    
    // More tactics = more sophisticated
    sophisticationScore += tacticsUsed * 2;
    
    // 2. Analyze topic transitions
    if (!metrics.topicTransitions.isEmpty()) {
        // Calculate transition diversity
        const int uniqueTransitions = metrics.topicTransitions.size();
        const int totalTransitions = std::accumulate(
            metrics.topicTransitions.begin(),
            metrics.topicTransitions.end(),
            0
        );
        
        // More unique transitions = more sophisticated
        sophisticationScore += qMin(uniqueTransitions * 2, 10);
        
        // Natural flow (not too many transitions)
        if (totalTransitions > 0 && uniqueTransitions > 0) {
            const double transitionRatio = 
                static_cast<double>(uniqueTransitions) / totalTransitions;
            if (transitionRatio > 0.3 && transitionRatio < 0.7) {
                sophisticationScore += 5; // Natural conversation flow
            }
        }
    }
    
    // 3. Analyze message timing and emotional manipulation
    if (!metrics.conversationFlow.isEmpty()) {
        // Check for natural timing variations
        QVector<qint64> timeDiffs;
        for (int i = 1; i < metrics.conversationFlow.size(); i++) {
            timeDiffs.append(
                metrics.conversationFlow[i].first - 
                metrics.conversationFlow[i-1].first
            );
        }
        
        if (!timeDiffs.isEmpty()) {
            // Calculate timing variance
            const double avgDiff = std::accumulate(
                timeDiffs.begin(), 
                timeDiffs.end(), 
                0.0
            ) / timeDiffs.size();
            
            double variance = 0;
            for (const auto diff : timeDiffs) {
                variance += (diff - avgDiff) * (diff - avgDiff);
            }
            variance /= timeDiffs.size();
            
            // Natural timing variations (not too regular, not too random)
            if (variance > 100 && variance < 10000) {
                sophisticationScore += 5;
            }
        }
        
        // Emotional manipulation analysis
        if (metrics.emotionalIntensity > 0) {
            const double avgEmotionalIntensity = 
                metrics.emotionalIntensity / metrics.conversationFlow.size();
            
            // Sophisticated emotional manipulation (not too obvious)
            if (avgEmotionalIntensity > 0.1 && avgEmotionalIntensity < 0.4) {
                sophisticationScore += 5;
            }
        }
    }
    
    // 4. Message characteristics analysis
    if (metrics.messageFrequency > 0) {
        // Not too frequent, not too sparse
        if (metrics.messageFrequency > 2 && metrics.messageFrequency < 20) {
            sophisticationScore += 3;
        }
        
        // Natural message length variation
        if (metrics.messageLength > 20 && metrics.messageLength < 200) {
            sophisticationScore += 3;
        }
        
        // Question frequency analysis
        if (metrics.questionFrequency > 10 && metrics.questionFrequency < 40) {
            sophisticationScore += 3;
        }
        
        // Link usage analysis
        if (metrics.linkFrequency > 0 && metrics.linkFrequency < 20) {
            sophisticationScore += 3;
        }
    }
    
    // Update TTP evidence based on sophistication score
    if (sophisticationScore >= 30) {
        ttpEvidence["Social Engineering"] += 5;
        // Add specific sophisticated tactics
        if (!dominantTactic.isEmpty()) {
            QString specificTactic = "Advanced " + dominantTactic + " manipulation";
            if (!_adversaries[adversary.id].observedTactics.contains(specificTactic)) {
                _adversaries[adversary.id].observedTactics.append(specificTactic);
            }
        }
    } else if (sophisticationScore >= 20) {
        ttpEvidence["Social Engineering"] += 3;
    } else if (sophisticationScore >= 10) {
        ttpEvidence["Social Engineering"] += 1;
    }
}

void CounterIntelligenceManager::analyzeCrossUserPatterns(
    const QMap<UserId, ConversationMetrics> &userMetrics,
    QMap<QString, int> &ttpEvidence) {
    
    // Analyze patterns across different targeted users
    QVector<double> emotionalIntensities;
    QVector<int> messageFrequencies;
    QVector<int> questionFrequencies;
    QSet<QString> commonTransitions;
    
    bool firstUser = true;
    for (auto it = userMetrics.begin(); it != userMetrics.end(); ++it) {
        const auto &metrics = it.value();
        
        emotionalIntensities.append(metrics.emotionalIntensity);
        messageFrequencies.append(metrics.messageFrequency);
        questionFrequencies.append(metrics.questionFrequency);
        
        // Track common topic transitions
        if (firstUser) {
            commonTransitions = QSet<QString>(
                metrics.topicTransitions.keys().begin(),
                metrics.topicTransitions.keys().end()
            );
            firstUser = false;
        } else {
            QSet<QString> currentTransitions(
                metrics.topicTransitions.keys().begin(),
                metrics.topicTransitions.keys().end()
            );
            commonTransitions = commonTransitions.intersect(currentTransitions);
        }
    }
    
    // Calculate consistency scores
    double emotionalConsistency = calculateConsistencyScore(emotionalIntensities);
    double messageFreqConsistency = calculateConsistencyScore(messageFrequencies);
    double questionFreqConsistency = calculateConsistencyScore(questionFrequencies);
    
    // High consistency across different targets suggests sophisticated automation
    // or well-planned social engineering
    int consistencyScore = 0;
    
    if (emotionalConsistency > 0.7) consistencyScore += 2;
    if (messageFreqConsistency > 0.7) consistencyScore += 2;
    if (questionFreqConsistency > 0.7) consistencyScore += 2;
    
    // Common manipulation patterns across targets
    if (!commonTransitions.isEmpty()) {
        consistencyScore += qMin(commonTransitions.size(), 5);
    }
    
    // Update TTP evidence based on cross-user analysis
    if (consistencyScore >= 8) {
        ttpEvidence["Social Engineering"] += 5;
        ttpEvidence["Technical"] += 3; // Suggests possible automation
    } else if (consistencyScore >= 5) {
        ttpEvidence["Social Engineering"] += 3;
    }
}

double CounterIntelligenceManager::calculateConsistencyScore(const QVector<double> &values) {
    if (values.isEmpty()) return 0.0;
    
    double sum = std::accumulate(values.begin(), values.end(), 0.0);
    double mean = sum / values.size();
    
    double variance = 0.0;
    for (const auto &value : values) {
        variance += (value - mean) * (value - mean);
    }
    variance /= values.size();
    
    // Convert variance to a 0-1 consistency score
    // Lower variance = higher consistency
    return 1.0 / (1.0 + sqrt(variance));
}

MessageSuspicionInfo CounterIntelligenceManager::analyzeMessageForSuspiciousPatterns(
    const QString &messageText,
    MsgId messageId,
    UserId senderId) {
    
    // Get or create metrics for this user's conversation
    ConversationMetrics metrics;
    if (Core::App().activeAccount().sessionExists()) {
        auto &session = Core::App().activeAccount().session();
        if (const auto user = session.data().userLoaded(senderId)) {
            auto history = session.data().history(user->id);
            // Get recent message history for context
            auto messages = history->getMessages(0, 50);
            
            // Calculate metrics from recent history
            calculateConversationMetrics(messages, metrics);
        }
    }
    
    // Detect patterns in this message
    auto patterns = detectSuspiciousPatterns(messageText, metrics);
    
    // Create suspicion info
    MessageSuspicionInfo info;
    info.messageId = messageId;
    info.patterns = patterns;
    info.analyzedTime = QDateTime::currentDateTime();
    info.updateOverallSuspicion();
    
    // Store the analysis
    _messageSuspicionInfo[messageId] = info;
    _userSuspiciousMessages[senderId].append(messageId);
    
    // If this is a highly suspicious message, fire the event
    if (info.overallSuspicionLevel >= 5) {
        _suspiciousPatternStream.fire_copy(info);
    }
    
    return info;
}

QVector<SuspiciousPattern> CounterIntelligenceManager::detectSuspiciousPatterns(
    const QString &messageText,
    const ConversationMetrics &metrics) {
    
    QVector<SuspiciousPattern> patterns;
    
    // Define pattern detection rules with regular expressions
    const QMap<SuspiciousPattern::TacticType, QPair<QString, QRegularExpression>> patternRules = {
        {SuspiciousPattern::TacticType::Urgency, {
            "Urgency/Time Pressure",
            QRegularExpression(R"((?:urgent|asap|emergency|deadline|quickly|hurry|immediate|now)\b|(?:need.*(?:right now|today|asap))|(?:by.*(?:end of|tomorrow|tonight)))", 
            QRegularExpression::CaseInsensitiveOption)
        }},
        {SuspiciousPattern::TacticType::Authority, {
            "Authority/Position Leverage",
            QRegularExpression(R"((?:as.*(?:manager|admin|supervisor|director|officer))|(?:corporate|compliance|policy|security|IT department|required by))",
            QRegularExpression::CaseInsensitiveOption)
        }},
        {SuspiciousPattern::TacticType::FearAppeal, {
            "Fear/Threat Appeal",
            QRegularExpression(R"((?:warning|alert|risk|threat|danger|security|breach|hack|compromise|violation|penalty|consequence))",
            QRegularExpression::CaseInsensitiveOption)
        }},
        {SuspiciousPattern::TacticType::Scarcity, {
            "Scarcity/Limitation",
            QRegularExpression(R"((?:limited|only|exclusive|rare|special|unique|one-time|expires?|deadline|last chance|running out|few remaining))",
            QRegularExpression::CaseInsensitiveOption)
        }},
        {SuspiciousPattern::TacticType::SocialProof, {
            "Social Proof/Consensus",
            QRegularExpression(R"((?:everyone|everybody|others?|people|team|colleagues|staff|employees?).*(?:already|have|doing|using|agreed|approved))",
            QRegularExpression::CaseInsensitiveOption)
        }},
        {SuspiciousPattern::TacticType::Reciprocity, {
            "Reciprocity/Exchange",
            QRegularExpression(R"((?:in return|favor|help.*back|owe|repay|give.*back|return.*favor|done for you|helped you))",
            QRegularExpression::CaseInsensitiveOption)
        }},
        {SuspiciousPattern::TacticType::CredentialHarvesting, {
            "Credential Harvesting",
            QRegularExpression(R"((?:verify|confirm|validate|authenticate|login|password|account|credentials?|access|token|2fa|two-factor|security code))",
            QRegularExpression::CaseInsensitiveOption)
        }},
        {SuspiciousPattern::TacticType::Deception, {
            "Deceptive Practices",
            QRegularExpression(R"((?:pretend|pose|fake|hidden|secret|private|confidential|classified|undisclosed|between us|don't.*tell|keep.*quiet))",
            QRegularExpression::CaseInsensitiveOption)
        }}
    };
    
    // Track evidence points for each pattern
    QMap<SuspiciousPattern::TacticType, QVector<QString>> evidencePoints;
    
    // Check each pattern
    for (auto it = patternRules.begin(); it != patternRules.end(); ++it) {
        const auto tacticType = it.key();
        const auto &patternName = it.value().first;
        const auto &regex = it.value().second;
        
        auto matches = regex.globalMatch(messageText);
        QVector<QPair<int, int>> matchRanges;
        
        while (matches.hasNext()) {
            auto match = matches.next();
            matchRanges.append({match.capturedStart(), match.capturedEnd()});
            evidencePoints[tacticType].append(match.captured());
        }
        
        if (!matchRanges.isEmpty()) {
            // Calculate suspicion level for this pattern
            int suspicionLevel = calculatePatternSuspicionLevel(
                messageText, tacticType, metrics);
            
            SuspiciousPattern pattern;
            pattern.tacticType = tacticType;
            pattern.suspicionLevel = suspicionLevel;
            pattern.tacticName = patternName;
            pattern.textRanges = matchRanges;
            pattern.highlightColor = SuspiciousPattern::getSuspicionColor(suspicionLevel);
            pattern.detectedTime = QDateTime::currentDateTime();
            pattern.explanation = generatePatternExplanation(
                tacticType, suspicionLevel, evidencePoints[tacticType]);
            
            patterns.append(pattern);
        }
    }
    
    return patterns;
}

int CounterIntelligenceManager::calculatePatternSuspicionLevel(
    const QString &messageText,
    SuspiciousPattern::TacticType tacticType,
    const ConversationMetrics &metrics) {
    
    int baseScore = 0;
    
    // Factor 1: Pattern density
    const int messageLength = messageText.length();
    const int patternCount = evidencePoints[tacticType].size();
    const double density = static_cast<double>(patternCount) / messageLength;
    
    if (density > 0.05) baseScore += 3;
    else if (density > 0.02) baseScore += 2;
    else baseScore += 1;
    
    // Factor 2: Context from conversation metrics
    if (metrics.messageFrequency > 0) {
        // Unusual timing patterns
        if (metrics.messageFrequency > 20) baseScore += 2;
        
        // High emotional intensity
        if (metrics.emotionalIntensity > 0.5) baseScore += 2;
        
        // Unusual question frequency
        if (metrics.questionFrequency > 40) baseScore += 1;
    }
    
    // Factor 3: Pattern-specific checks
    switch (tacticType) {
        case SuspiciousPattern::TacticType::Urgency:
            // Check for multiple urgency indicators
            if (messageText.contains(QRegularExpression("urgent.*immediate|asap.*quickly",
                QRegularExpression::CaseInsensitiveOption))) {
                baseScore += 2;
            }
            break;
            
        case SuspiciousPattern::TacticType::CredentialHarvesting:
            // Multiple credential-related terms
            if (messageText.contains(QRegularExpression("password.*account|login.*credentials",
                QRegularExpression::CaseInsensitiveOption))) {
                baseScore += 3;
            }
            break;
            
        case SuspiciousPattern::TacticType::FearAppeal:
            // Combined fear with urgency
            if (messageText.contains(QRegularExpression("urgent.*risk|immediate.*threat",
                QRegularExpression::CaseInsensitiveOption))) {
                baseScore += 2;
            }
            break;
            
        default:
            break;
    }
    
    // Factor 4: Combination with other patterns
    for (const auto &otherPattern : patterns) {
        if (otherPattern.tacticType != tacticType) {
            // Certain combinations are more suspicious
            if ((tacticType == SuspiciousPattern::TacticType::Urgency &&
                 otherPattern.tacticType == SuspiciousPattern::TacticType::FearAppeal) ||
                (tacticType == SuspiciousPattern::TacticType::Authority &&
                 otherPattern.tacticType == SuspiciousPattern::TacticType::CredentialHarvesting)) {
                baseScore += 2;
            } else {
                baseScore += 1;
            }
        }
    }
    
    // Ensure score is within 1-10 range
    return qBound(1, baseScore, 10);
}

QString CounterIntelligenceManager::generatePatternExplanation(
    SuspiciousPattern::TacticType tacticType,
    int suspicionLevel,
    const QVector<QString> &evidencePoints) {
    
    QString explanation;
    
    // Start with the basic pattern description
    switch (tacticType) {
        case SuspiciousPattern::TacticType::Urgency:
            explanation = "Creates artificial time pressure";
            break;
        case SuspiciousPattern::TacticType::Authority:
            explanation = "Leverages authority or position";
            break;
        case SuspiciousPattern::TacticType::FearAppeal:
            explanation = "Uses fear or threats";
            break;
        case SuspiciousPattern::TacticType::Scarcity:
            explanation = "Emphasizes limitations or scarcity";
            break;
        case SuspiciousPattern::TacticType::SocialProof:
            explanation = "Appeals to group behavior";
            break;
        case SuspiciousPattern::TacticType::Reciprocity:
            explanation = "Creates sense of obligation";
            break;
        case SuspiciousPattern::TacticType::CredentialHarvesting:
            explanation = "Attempts to collect sensitive information";
            break;
        case SuspiciousPattern::TacticType::Deception:
            explanation = "Shows signs of deceptive behavior";
            break;
        default:
            explanation = "Suspicious communication pattern";
    }
    
    // Add suspicion level context
    if (suspicionLevel >= 8) {
        explanation += " (High Risk)";
    } else if (suspicionLevel >= 5) {
        explanation += " (Medium Risk)";
    } else {
        explanation += " (Low Risk)";
    }
    
    // Add evidence if available
    if (!evidencePoints.isEmpty()) {
        explanation += "\nEvidence: ";
        QStringList evidence;
        for (const auto &point : evidencePoints) {
            evidence.append(QString("\"%1\"").arg(point));
            if (evidence.size() >= 3) break; // Limit to 3 examples
        }
        explanation += evidence.join(", ");
        
        if (evidencePoints.size() > 3) {
            explanation += QString(" and %1 more").arg(evidencePoints.size() - 3);
        }
    }
    
    return explanation;
}

QVector<SuspiciousPattern> CounterIntelligenceManager::getActivePatternsForMessage(
    MsgId messageId) const {
    
    QVector<SuspiciousPattern> activePatterns;
    
    if (_messageSuspicionInfo.contains(messageId)) {
        const auto &info = _messageSuspicionInfo[messageId];
        for (const auto &pattern : info.patterns) {
            if (pattern.isActive) {
                activePatterns.append(pattern);
            }
        }
    }
    
    return activePatterns;
}

void CounterIntelligenceManager::updatePatternStatus(
    MsgId messageId,
    int patternIndex,
    bool isActive) {
    
    if (_messageSuspicionInfo.contains(messageId)) {
        auto &info = _messageSuspicionInfo[messageId];
        if (patternIndex >= 0 && patternIndex < info.patterns.size()) {
            info.patterns[patternIndex].isActive = isActive;
            info.updateOverallSuspicion();
            
            // Fire event if status change affects overall suspicion
            if (info.overallSuspicionLevel >= 5) {
                _suspiciousPatternStream.fire_copy(info);
            }
        }
    }
}

QVector<MessageSuspicionInfo> CounterIntelligenceManager::getSuspiciousMessagesForUser(
    UserId userId) const {
    
    QVector<MessageSuspicionInfo> result;
    
    if (_userSuspiciousMessages.contains(userId)) {
        const auto &messageIds = _userSuspiciousMessages[userId];
        for (const auto &messageId : messageIds) {
            if (_messageSuspicionInfo.contains(messageId)) {
                result.append(_messageSuspicionInfo[messageId]);
            }
        }
    }
    
    return result;
}

rpl::producer<MessageSuspicionInfo> CounterIntelligenceManager::suspiciousPatternDetected() const {
    return _suspiciousPatternStream.events();
}

QString CounterIntelligenceManager::getPatternExplanation(
    SuspiciousPattern::TacticType type) const {
    
    switch (type) {
        case SuspiciousPattern::TacticType::Urgency:
            return "Creates artificial time pressure to force quick decisions";
        case SuspiciousPattern::TacticType::Authority:
            return "Misuses authority or position to compel compliance";
        case SuspiciousPattern::TacticType::FearAppeal:
            return "Exploits fear or threats to manipulate behavior";
        case SuspiciousPattern::TacticType::Scarcity:
            return "Uses artificial scarcity to pressure decisions";
        case SuspiciousPattern::TacticType::SocialProof:
            return "Leverages group behavior to influence actions";
        case SuspiciousPattern::TacticType::Reciprocity:
            return "Creates artificial obligation to encourage compliance";
        case SuspiciousPattern::TacticType::CredentialHarvesting:
            return "Attempts to collect sensitive credentials or information";
        case SuspiciousPattern::TacticType::Deception:
            return "Shows signs of intentional deception or manipulation";
        default:
            return "Unknown suspicious pattern type";
    }
}

} // namespace Data 