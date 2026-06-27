/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "data/data_location_randomization.h"

#include "data/data_session.h"
#include "data/counterintelligence_features.h"
#include "storage/localstorage.h"
#include "storage/storage_account.h"

#include <QtCore/QCryptographicHash>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QJsonArray>
#include <QtCore/QTimer>
#include <QtCore/QRegularExpression>
#include <QtCore/QUuid>
#include <QtCore/QStandardPaths>
#include <QtCore/QDir>
#include <QtCore/QRandomGenerator>

#include <cmath>

namespace Data {

namespace {

// Constants for location randomization
constexpr auto kLocationDataKey = "location_randomization_data";
constexpr auto kLocationSettingsKey = "location_randomization_settings";
constexpr auto kMaxLocationHistory = 100;
constexpr auto kDefaultPoolSize = 100;
constexpr auto kDecoyRatio = 20; // 20% decoy locations
constexpr auto kCoordinateNoiseRadius = 5.0; // 5km radius for noise

// Helper to generate cryptographically secure random values
uint32_t generateCryptoRandom(uint32_t min, uint32_t max) {
    auto *generator = QRandomGenerator::global();
    return generator->bounded(min, max + 1);
}

double generateCryptoRandomDouble() {
    auto *generator = QRandomGenerator::global();
    return generator->generateDouble();
}

// Helper to calculate distance between two geographic points
double calculateDistance(double lat1, double lon1, double lat2, double lon2) {
    const double R = 6371.0; // Earth's radius in km
    const double dLat = (lat2 - lat1) * M_PI / 180.0;
    const double dLon = (lon2 - lon1) * M_PI / 180.0;
    const double a = sin(dLat/2) * sin(dLat/2) +
                     cos(lat1 * M_PI / 180.0) * cos(lat2 * M_PI / 180.0) *
                     sin(dLon/2) * sin(dLon/2);
    const double c = 2 * atan2(sqrt(a), sqrt(1-a));
    return R * c;
}

// Coordinate noise generation
QPair<double, double> applyCoordinateNoise(double lat, double lon, double radiusKm) {
    const double r = radiusKm * sqrt(generateCryptoRandomDouble());
    const double theta = generateCryptoRandomDouble() * 2 * M_PI;

    // Convert to degrees (approximate)
    const double deltaLat = (r * cos(theta)) / 111.0; // ~111 km per degree latitude
    const double deltaLon = (r * sin(theta)) / (111.0 * cos(lat * M_PI / 180.0));

    return qMakePair(lat + deltaLat, lon + deltaLon);
}

} // namespace

// LocationProfile serialization
QByteArray LocationProfile::serialize() const {
    QJsonObject obj;
    obj["locationId"] = locationId;
    obj["displayName"] = displayName;
    obj["address"] = address;
    obj["city"] = city;
    obj["state"] = state;
    obj["postalCode"] = postalCode;
    obj["latitude"] = latitude;
    obj["longitude"] = longitude;
    obj["timezone"] = timezone;
    obj["businessTypes"] = QJsonArray::fromStringList(businessTypes);
    obj["credibilityScore"] = credibilityScore;
    obj["lastUsed"] = lastUsed.toString(Qt::ISODate);
    obj["regionId"] = regionId;
    obj["isDecoy"] = isDecoy;

    return QJsonDocument(obj).toJson(QJsonDocument::Compact);
}

LocationProfile LocationProfile::deserialize(const QByteArray &data) {
    LocationProfile profile;

    QJsonParseError error;
    QJsonDocument doc = QJsonDocument::fromJson(data, &error);
    if (error.error != QJsonParseError::NoError || !doc.isObject()) {
        return profile;
    }

    QJsonObject obj = doc.object();
    profile.locationId = obj["locationId"].toString();
    profile.displayName = obj["displayName"].toString();
    profile.address = obj["address"].toString();
    profile.city = obj["city"].toString();
    profile.state = obj["state"].toString();
    profile.postalCode = obj["postalCode"].toString();
    profile.latitude = obj["latitude"].toDouble();
    profile.longitude = obj["longitude"].toDouble();
    profile.timezone = obj["timezone"].toString();

    QJsonArray businessArray = obj["businessTypes"].toArray();
    for (const auto &value : businessArray) {
        profile.businessTypes.append(value.toString());
    }

    profile.credibilityScore = obj["credibilityScore"].toInt();
    profile.lastUsed = QDateTime::fromString(obj["lastUsed"].toString(), Qt::ISODate);
    profile.regionId = obj["regionId"].toString();
    profile.isDecoy = obj["isDecoy"].toBool();

    return profile;
}

QString LocationProfile::generateFingerprint() const {
    QString data = QString("%1|%2|%3|%4").arg(
        address, city, state, QString::number(latitude, 'f', 6));
    return QCryptographicHash::hash(data.toUtf8(), QCryptographicHash::Sha256).toHex().left(16);
}

// PhoneNumberAnalyzer implementation
PhoneNumberAnalyzer::PhoneNumberAnalyzer() {
    initializeCountryData();
    initializeAreaCodeMappings();
}

PhoneAnalysis PhoneNumberAnalyzer::analyzePhoneNumber(const QString &phoneNumber) {
    PhoneAnalysis analysis;

    QString normalized = normalizePhoneNumber(phoneNumber);
    if (normalized.isEmpty()) {
        return analysis;
    }

    analysis.countryCode = extractCountryCode(normalized);
    if (analysis.countryCode.isEmpty()) {
        return analysis;
    }

    analysis.areaCode = extractAreaCode(normalized, analysis.countryCode);

    // Map to region
    if (_countryCodeToRegion.contains(analysis.countryCode)) {
        QString baseRegion = _countryCodeToRegion[analysis.countryCode];

        // Refine based on area code if available
        if (!analysis.areaCode.isEmpty() &&
            _areaCodeToRegion.contains(analysis.countryCode) &&
            _areaCodeToRegion[analysis.countryCode].contains(analysis.areaCode)) {
            analysis.region = _areaCodeToRegion[analysis.countryCode][analysis.areaCode];
        } else {
            analysis.region = baseRegion;
        }

        // Set timezone and cultural context
        if (_regionToTimezones.contains(analysis.region)) {
            analysis.timezone = _regionToTimezones[analysis.region].first();
        }
        if (_regionToCultures.contains(analysis.region)) {
            analysis.culturalContext = _regionToCultures[analysis.region];
        }

        // Set population density (simplified)
        analysis.populationDensity = 5; // Default medium density

        analysis.isValid = true;
    }

    return analysis;
}

QString PhoneNumberAnalyzer::extractCountryCode(const QString &phoneNumber) {
    // Simple country code extraction
    if (phoneNumber.startsWith("+1")) return "+1";
    if (phoneNumber.startsWith("+44")) return "+44";
    if (phoneNumber.startsWith("+49")) return "+49";
    if (phoneNumber.startsWith("+33")) return "+33";
    if (phoneNumber.startsWith("+39")) return "+39";
    if (phoneNumber.startsWith("+34")) return "+34";
    if (phoneNumber.startsWith("+7")) return "+7";
    if (phoneNumber.startsWith("+86")) return "+86";
    if (phoneNumber.startsWith("+81")) return "+81";
    if (phoneNumber.startsWith("+91")) return "+91";

    return QString();
}

QString PhoneNumberAnalyzer::extractAreaCode(const QString &phoneNumber, const QString &countryCode) {
    QString withoutCountry = phoneNumber.mid(countryCode.length());

    if (countryCode == "+1") {
        // North American numbering plan
        if (withoutCountry.length() >= 3) {
            return withoutCountry.left(3);
        }
    } else if (countryCode == "+44") {
        // UK numbering plan
        if (withoutCountry.length() >= 2) {
            return withoutCountry.left(2);
        }
    } else if (countryCode == "+49") {
        // German numbering plan
        if (withoutCountry.length() >= 3) {
            return withoutCountry.left(3);
        }
    }

    return QString();
}

QStringList PhoneNumberAnalyzer::getSupportedCountries() {
    return {"US", "CA", "UK", "DE", "FR", "IT", "ES", "RU", "CN", "JP", "IN"};
}

bool PhoneNumberAnalyzer::isValidPhoneNumber(const QString &phoneNumber) {
    QString normalized = normalizePhoneNumber(phoneNumber);
    return !normalized.isEmpty() && !extractCountryCode(normalized).isEmpty();
}

QString PhoneNumberAnalyzer::normalizePhoneNumber(const QString &phoneNumber) {
    QString normalized = phoneNumber;
    normalized.remove(QRegularExpression("[\\s\\-\\(\\)\\.]"));

    if (!normalized.startsWith("+")) {
        return QString(); // Require international format
    }

    return normalized;
}

void PhoneNumberAnalyzer::initializeCountryData() {
    // Map country codes to broad regions
    _countryCodeToRegion["+1"] = "NA_GENERAL";
    _countryCodeToRegion["+44"] = "EU_WESTERN";
    _countryCodeToRegion["+49"] = "EU_CENTRAL";
    _countryCodeToRegion["+33"] = "EU_WESTERN";
    _countryCodeToRegion["+39"] = "EU_SOUTHERN";
    _countryCodeToRegion["+34"] = "EU_SOUTHERN";
    _countryCodeToRegion["+7"] = "EU_EASTERN";
    _countryCodeToRegion["+86"] = "AS_EASTERN";
    _countryCodeToRegion["+81"] = "AS_EASTERN";
    _countryCodeToRegion["+91"] = "AS_SOUTHERN";

    // Regional timezones
    _regionToTimezones["NA_GENERAL"] = {"America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles"};
    _regionToTimezones["EU_WESTERN"] = {"Europe/London", "Europe/Paris"};
    _regionToTimezones["EU_CENTRAL"] = {"Europe/Berlin", "Europe/Prague"};
    _regionToTimezones["EU_SOUTHERN"] = {"Europe/Rome", "Europe/Madrid"};
    _regionToTimezones["EU_EASTERN"] = {"Europe/Moscow", "Europe/Kiev"};
    _regionToTimezones["AS_EASTERN"] = {"Asia/Shanghai", "Asia/Tokyo"};
    _regionToTimezones["AS_SOUTHERN"] = {"Asia/Kolkata", "Asia/Dubai"};

    // Regional cultures
    _regionToCultures["NA_GENERAL"] = {"English", "Spanish", "French"};
    _regionToCultures["EU_WESTERN"] = {"English", "French"};
    _regionToCultures["EU_CENTRAL"] = {"German", "Czech"};
    _regionToCultures["EU_SOUTHERN"] = {"Italian", "Spanish"};
    _regionToCultures["EU_EASTERN"] = {"Russian", "Ukrainian"};
    _regionToCultures["AS_EASTERN"] = {"Chinese", "Japanese"};
    _regionToCultures["AS_SOUTHERN"] = {"Hindi", "Arabic"};
}

void PhoneNumberAnalyzer::initializeAreaCodeMappings() {
    // US area code to region mapping (sample)
    QMap<QString, QString> usAreaCodes;
    usAreaCodes["617"] = "NA_NORTHEAST";  // Boston
    usAreaCodes["212"] = "NA_NORTHEAST";  // NYC
    usAreaCodes["415"] = "NA_WEST";       // San Francisco
    usAreaCodes["310"] = "NA_WEST";       // Los Angeles
    usAreaCodes["312"] = "NA_MIDWEST";    // Chicago
    usAreaCodes["713"] = "NA_SOUTH";      // Houston
    usAreaCodes["404"] = "NA_SOUTH";      // Atlanta
    _areaCodeToRegion["+1"] = usAreaCodes;

    // UK area codes (sample)
    QMap<QString, QString> ukAreaCodes;
    ukAreaCodes["20"] = "EU_UK_LONDON";   // London
    ukAreaCodes["161"] = "EU_UK_NORTH";   // Manchester
    ukAreaCodes["121"] = "EU_UK_MIDLANDS"; // Birmingham
    _areaCodeToRegion["+44"] = ukAreaCodes;

    // German area codes (sample)
    QMap<QString, QString> deAreaCodes;
    deAreaCodes["30"] = "EU_DE_NORTH";    // Berlin
    deAreaCodes["89"] = "EU_DE_SOUTH";    // Munich
    deAreaCodes["40"] = "EU_DE_NORTH";    // Hamburg
    _areaCodeToRegion["+49"] = deAreaCodes;
}

// GeographicMapper implementation
GeographicMapper::GeographicMapper() {
    initializeRegions();
    calculateRegionCompatibility();
}

GeographicRegion GeographicMapper::mapAreaCodeToRegion(
    const QString &countryCode,
    const QString &areaCode) {

    GeographicRegion region;

    // This would typically query a comprehensive database
    // For now, return a default region based on country
    if (countryCode == "+1") {
        region.regionId = "NA_GENERAL";
        region.displayName = "North America";
        region.timezones = {"America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles"};
        region.languages = {"English", "Spanish", "French"};
        region.coordinateBounds[0] = 25.0;  // minLat
        region.coordinateBounds[1] = 49.0;  // maxLat
        region.coordinateBounds[2] = -125.0; // minLon
        region.coordinateBounds[3] = -66.0;  // maxLon
        region.credibilityWeight = 8;
    }

    return region;
}

QStringList GeographicMapper::getCompatibleRegions(const QString &primaryRegion) {
    if (_regionCompatibility.contains(primaryRegion)) {
        return _regionCompatibility[primaryRegion];
    }
    return QStringList();
}

bool GeographicMapper::areRegionsCompatible(const QString &region1, const QString &region2) {
    return getCompatibleRegions(region1).contains(region2);
}

QVector<GeographicRegion> GeographicMapper::getAllRegions() {
    QVector<GeographicRegion> regions;
    for (auto it = _regions.constBegin(); it != _regions.constEnd(); ++it) {
        regions.append(it.value());
    }
    return regions;
}

GeographicRegion GeographicMapper::getRegion(const QString &regionId) {
    return _regions.value(regionId, GeographicRegion{});
}

QStringList GeographicMapper::getRegionTimezones(const QString &regionId) {
    if (_regions.contains(regionId)) {
        return _regions[regionId].timezones;
    }
    return QStringList();
}

void GeographicMapper::initializeRegions() {
    // Initialize comprehensive region database
    // This would typically be loaded from a data file

    GeographicRegion naGeneral;
    naGeneral.regionId = "NA_GENERAL";
    naGeneral.displayName = "North America";
    naGeneral.timezones = {"America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles"};
    naGeneral.languages = {"English", "Spanish", "French"};
    naGeneral.coordinateBounds[0] = 25.0;
    naGeneral.coordinateBounds[1] = 49.0;
    naGeneral.coordinateBounds[2] = -125.0;
    naGeneral.coordinateBounds[3] = -66.0;
    naGeneral.credibilityWeight = 8;
    _regions[naGeneral.regionId] = naGeneral;

    // Add more regions as needed...
}

void GeographicMapper::calculateRegionCompatibility() {
    // Calculate which regions are compatible for randomization
    // Compatible regions should have similar characteristics

    _regionCompatibility["NA_GENERAL"] = {"NA_NORTHEAST", "NA_WEST", "NA_MIDWEST", "NA_SOUTH"};
    _regionCompatibility["EU_WESTERN"] = {"EU_CENTRAL", "EU_SOUTHERN"};
    // Add more compatibility mappings...
}

// LocationPoolManager implementation
LocationPoolManager::LocationPoolManager() {
    seedLocationPools();
}

QVector<LocationProfile> LocationPoolManager::generateLocationPool(
    const QString &regionId,
    int poolSize) {

    QVector<LocationProfile> pool;
    GeographicMapper mapper;
    GeographicRegion region = mapper.getRegion(regionId);

    if (region.regionId.isEmpty()) {
        return pool;
    }

    for (int i = 0; i < poolSize; ++i) {
        LocationProfile location = generateRealisticLocation(region);
        if (!location.locationId.isEmpty()) {
            pool.append(location);
        }
    }

    return pool;
}

LocationProfile LocationPoolManager::selectRandomLocation(
    const QString &regionId,
    const QStringList &excludeRecent) {

    if (!_locationPools.contains(regionId) || _locationPools[regionId].isEmpty()) {
        // Generate new pool if none exists
        _locationPools[regionId] = generateLocationPool(regionId, kDefaultPoolSize);
    }

    QVector<LocationProfile> &pool = _locationPools[regionId];
    QVector<LocationProfile> available;

    for (const auto &location : pool) {
        if (!excludeRecent.contains(location.locationId)) {
            available.append(location);
        }
    }

    if (available.isEmpty()) {
        // If all locations are excluded, use the least recently used
        std::sort(pool.begin(), pool.end(), [](const LocationProfile &a, const LocationProfile &b) {
            return a.lastUsed < b.lastUsed;
        });
        return pool.first();
    }

    // Select random location from available
    int index = generateCryptoRandom(0, available.size() - 1);
    return available[index];
}

void LocationPoolManager::markLocationUsed(const QString &locationId) {
    QDateTime now = QDateTime::currentDateTime();

    for (auto &pool : _locationPools) {
        for (auto &location : pool) {
            if (location.locationId == locationId) {
                location.lastUsed = now;
                break;
            }
        }
    }

    // Add to recent history
    for (auto &history : _recentLocationHistory) {
        history.prepend(locationId);
        if (history.size() > kMaxLocationHistory) {
            history.removeLast();
        }
    }
}

LocationProfile LocationPoolManager::generateRealisticLocation(const GeographicRegion &region) {
    LocationProfile location;
    location.locationId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    location.regionId = region.regionId;

    // Generate coordinates within region bounds
    double latRange = region.coordinateBounds[1] - region.coordinateBounds[0];
    double lonRange = region.coordinateBounds[3] - region.coordinateBounds[2];

    location.latitude = region.coordinateBounds[0] + (generateCryptoRandomDouble() * latRange);
    location.longitude = region.coordinateBounds[2] + (generateCryptoRandomDouble() * lonRange);

    // Generate realistic address
    location.address = generateRealisticAddress(region);

    // Set other properties based on region
    if (region.regionId.startsWith("NA_")) {
        location.city = "Springfield";  // Generic American city name
        location.state = "MA";
        location.postalCode = QString::number(generateCryptoRandom(10000, 99999));
    } else if (region.regionId.startsWith("EU_")) {
        location.city = "Cambridge";    // Generic European city name
        location.state = "England";
        location.postalCode = "CB1 2AB";
    }

    location.displayName = QString("%1 Business District").arg(location.city);
    location.timezone = region.timezones.isEmpty() ? "UTC" : region.timezones.first();
    location.businessTypes = generateBusinessTypes(region);
    location.credibilityScore = generateCryptoRandom(6, 9); // High credibility
    location.lastUsed = QDateTime::currentDateTime().addDays(-generateCryptoRandom(1, 30));

    return location;
}

QString LocationPoolManager::generateRealisticAddress(const GeographicRegion &region) {
    QStringList streetNumbers = {"100", "200", "300", "400", "500", "1000", "1200", "1500"};
    QStringList streetNames;

    if (region.regionId.startsWith("NA_")) {
        streetNames = {"Main Street", "Oak Avenue", "Park Drive", "Business Boulevard",
                      "Technology Way", "Commerce Street", "Industrial Drive"};
    } else {
        streetNames = {"High Street", "Victoria Road", "Church Lane", "Mill Street",
                      "Market Square", "Business Park", "Technology Centre"};
    }

    QString number = streetNumbers[generateCryptoRandom(0, streetNumbers.size() - 1)];
    QString street = streetNames[generateCryptoRandom(0, streetNames.size() - 1)];

    return QString("%1 %2").arg(number, street);
}

QStringList LocationPoolManager::generateBusinessTypes(const GeographicRegion &region) {
    QStringList types = {"Office", "Technology", "Consulting", "Research", "Finance"};

    // Add region-specific business types
    if (region.regionId.contains("TECH")) {
        types.append({"Software Development", "Data Center", "Innovation Lab"});
    }

    int count = generateCryptoRandom(1, 3);
    QStringList result;
    for (int i = 0; i < count; ++i) {
        QString type = types[generateCryptoRandom(0, types.size() - 1)];
        if (!result.contains(type)) {
            result.append(type);
        }
    }

    return result;
}

// LocationRandomizationManager implementation
LocationRandomizationManager::LocationRandomizationManager(QObject *parent)
    : QObject(parent)
    , _phoneAnalyzer(std::make_unique<PhoneNumberAnalyzer>())
    , _geoMapper(std::make_unique<GeographicMapper>())
    , _poolManager(std::make_unique<LocationPoolManager>())
    , _randomizer(std::make_unique<SmartLocationRandomizer>(_poolManager.get()))
{
    _initialized = QDateTime::currentDateTime();
}

LocationRandomizationManager::~LocationRandomizationManager() = default;

void LocationRandomizationManager::initialize(const PrivacySettings &settings) {
    _settings = settings;
    setupRotationTimer();
    updateAuditLog("Location Randomization System initialized");
}

LocationProfile LocationRandomizationManager::getCurrentLocation() {
    if (_currentLocation.locationId.isEmpty()) {
        performLocationRotation();
    }
    return _currentLocation;
}

void LocationRandomizationManager::setUserPhoneNumber(const QString &phoneNumber) {
    _userPhoneAnalysis = _phoneAnalyzer->analyzePhoneNumber(phoneNumber);
    updateAuditLog(QString("Phone analysis updated for region: %1").arg(_userPhoneAnalysis.region));

    // Force location rotation to match new phone analysis
    if (_userPhoneAnalysis.isValid) {
        performLocationRotation();
    }
}

void LocationRandomizationManager::forceLocationRotation() {
    performLocationRotation();
    updateAuditLog("Manual location rotation performed");
}

QVariantMap LocationRandomizationManager::generateEnhancedHoneypotLocation(const QString &context) {
    QVariantMap honeypot;

    if (_userPhoneAnalysis.isValid) {
        LocationProfile decoy = generateContextualDecoy(context);

        honeypot["facility"] = decoy.displayName;
        honeypot["address"] = decoy.address;
        honeypot["city"] = decoy.city;
        honeypot["state"] = decoy.state;
        honeypot["coordinates"] = QString("%1° N, %2° W").arg(
            QString::number(decoy.latitude, 'f', 4),
            QString::number(qAbs(decoy.longitude), 'f', 4));
        honeypot["security_level"] = "Restricted Access";
        honeypot["context"] = context;
        honeypot["generated_time"] = QDateTime::currentDateTime().toString(Qt::ISODate);

        // // emit decoyLocationGenerated(decoy);
        updateAuditLog(QString("Enhanced honeypot location generated: %1").arg(decoy.displayName));
    } else {
        // Fallback to generic location
        honeypot["facility"] = "Research Facility";
        honeypot["address"] = "1000 Innovation Drive";
        honeypot["city"] = "Springfield";
        honeypot["state"] = "MA";
        honeypot["coordinates"] = "42.3601° N, 71.0589° W";
        honeypot["security_level"] = "Restricted Access";
    }

    return honeypot;
}

void LocationRandomizationManager::performLocationRotation() {
    if (!_userPhoneAnalysis.isValid) {
        updateAuditLog("Cannot rotate location: no valid phone analysis");
        return;
    }

    // Get recent location history for exclusion
    QStringList recentHistory = _randomizer->getLocationHistory(10);

    // Select new location
    LocationProfile newLocation = _randomizer->selectLocation(_userPhoneAnalysis, _settings.policy);

    if (!newLocation.locationId.isEmpty()) {
        _currentLocation = newLocation;
        _poolManager->markLocationUsed(newLocation.locationId);
        ++_rotationCount;

        // // emit locationRotated(newLocation);
        updateAuditLog(QString("Location rotated to: %1").arg(newLocation.displayName));
    }
}

void LocationRandomizationManager::updateAuditLog(const QString &event) {
    if (_settings.auditModeEnabled) {
        QString timestamp = QDateTime::currentDateTime().toString(Qt::ISODate);
        QString logEntry = QString("[%1] %2").arg(timestamp, event);

        _auditLog.prepend(logEntry);
        if (_auditLog.size() > 1000) { // Limit audit log size
            _auditLog.removeLast();
        }

        // // emit auditLogUpdated();
    }
}

LocationProfile LocationRandomizationManager::generateContextualDecoy(const QString &context) {
    // Generate a decoy location that fits the context
    LocationProfile decoy = _poolManager->selectRandomLocation(_userPhoneAnalysis.region);
    decoy.isDecoy = true;
    decoy.locationId = QUuid::createUuid().toString(QUuid::WithoutBraces);

    // Customize based on context
    if (context.contains("research", Qt::CaseInsensitive)) {
        decoy.displayName = QString("%1 Research Center").arg(decoy.city);
        decoy.businessTypes = {"Research", "Development", "Innovation"};
    } else if (context.contains("finance", Qt::CaseInsensitive)) {
        decoy.displayName = QString("%1 Financial District").arg(decoy.city);
        decoy.businessTypes = {"Finance", "Banking", "Investment"};
    }

    // Add coordinate noise for additional privacy
    if (_randomizer) {
        _randomizer->addCoordinateNoise(decoy, _settings.policy.noiseRadius);
    }

    ++_decoyCount;
    return decoy;
}

void LocationRandomizationManager::setupRotationTimer() {
    if (_rotationTimer) {
        _rotationTimer->stop();
        delete _rotationTimer;
    }

    _rotationTimer = new QTimer(this);
    connect(_rotationTimer, &QTimer::timeout, this, &LocationRandomizationManager::onRotationTimerTriggered);

    int intervalMs = _settings.rotationIntervalHours * 60 * 60 * 1000;
    _rotationTimer->start(intervalMs);
}

void LocationRandomizationManager::onRotationTimerTriggered() {
    if (_settings.enableLocationRandomization) {
        performLocationRotation();
    }
}

void LocationRandomizationManager::integrateWithHoneypotSystem(CounterIntelligenceManager *ci) {
    _counterIntelManager = ci;
    updateAuditLog("Integrated with counterintelligence system");
}

QStringList LocationRandomizationManager::getPrivacyAuditLog() {
    return _auditLog;
}

QString LocationRandomizationManager::getSystemStatus() {
    QStringList status;
    status << QString("Status: %1").arg(_settings.enableLocationRandomization ? "Active" : "Inactive");
    status << QString("Current Location: %1").arg(_currentLocation.displayName);
    status << QString("Region: %1").arg(_userPhoneAnalysis.region);
    status << QString("Rotations: %1").arg(_rotationCount);
    status << QString("Decoys Generated: %1").arg(_decoyCount);
    status << QString("Uptime: %1 hours").arg(_initialized.secsTo(QDateTime::currentDateTime()) / 3600);

    return status.join("\n");
}

// SmartLocationRandomizer implementation
SmartLocationRandomizer::SmartLocationRandomizer(LocationPoolManager *poolManager)
    : _poolManager(poolManager) {
}

LocationProfile SmartLocationRandomizer::selectLocation(
    const PhoneAnalysis &phoneAnalysis,
    const RandomizationPolicy &policy) {

    if (!phoneAnalysis.isValid) {
        return LocationProfile{};
    }

    QStringList excludeList = getLocationHistory(policy.maxLocationReuse);
    LocationProfile location = _poolManager->selectRandomLocation(phoneAnalysis.region, excludeList);

    if (!location.locationId.isEmpty()) {
        // Add coordinate noise for privacy
        addCoordinateNoise(location, policy.noiseRadius);

        // Update selection history
        _locationHistory.prepend(location.locationId);
        if (_locationHistory.size() > kMaxLocationHistory) {
            _locationHistory.removeLast();
        }

        // Update usage statistics
        _locationUsageCount[location.locationId]++;
        _lastRotationTime[location.locationId] = QDateTime::currentDateTime();

        // Update entropy calculation
        calculateSelectionEntropy();
    }

    return location;
}

void SmartLocationRandomizer::addCoordinateNoise(LocationProfile &location, double radiusKm) {
    auto noisyCoords = applyCoordinateNoise(location.latitude, location.longitude, radiusKm);
    location.latitude = noisyCoords.first;
    location.longitude = noisyCoords.second;
}

QStringList SmartLocationRandomizer::getLocationHistory(int maxHistory) {
    return _locationHistory.mid(0, qMin(maxHistory, _locationHistory.size()));
}

double SmartLocationRandomizer::calculateSelectionEntropy() {
    // Calculate entropy of recent selections for pattern detection
    QMap<QString, int> recentCounts;
    int recentSize = qMin(50, _locationHistory.size());

    for (int i = 0; i < recentSize; ++i) {
        recentCounts[_locationHistory[i]]++;
    }

    double entropy = 0.0;
    for (auto it = recentCounts.constBegin(); it != recentCounts.constEnd(); ++it) {
        double p = static_cast<double>(it.value()) / recentSize;
        entropy -= p * log2(p);
    }

    _selectionEntropy.append(entropy);
    if (_selectionEntropy.size() > 100) {
        _selectionEntropy.removeFirst();
    }
}

uint32_t SmartLocationRandomizer::generateSecureRandom(uint32_t min, uint32_t max) {
    return generateCryptoRandom(min, max);
}

double SmartLocationRandomizer::generateSecureRandomDouble() {
    return generateCryptoRandomDouble();
}

} // namespace Data
namespace Data {
void LocationRandomizationManager::onMessageCountChanged(int) {}
void LocationPoolManager::seedLocationPools() {}
}
