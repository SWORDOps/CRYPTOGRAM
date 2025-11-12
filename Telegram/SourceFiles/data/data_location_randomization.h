/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "data/data_peer.h"
#include "data/data_session.h"
#include "data/counterintelligence_features.h"

#include <QtCore/QDateTime>
#include <QtCore/QMap>
#include <QtCore/QSet>
#include <QtCore/QVector>
#include <QtCore/QString>
#include <QtCore/QVariantMap>

namespace Data {

// Forward declarations
class CounterIntelligenceManager;

struct PhoneAnalysis {
    QString countryCode;           // +1, +44, +49, etc.
    QString areaCode;              // 617, 020, 030, etc.
    QString region;                // "North America", "Europe", etc.
    QString timezone;              // "America/New_York", "Europe/London"
    QStringList culturalContext;   // Languages, cultural markers
    int populationDensity;         // 1-10 scale for realism
    bool isValid = false;          // Whether analysis succeeded
};

struct GeographicRegion {
    QString regionId;              // "NA_NORTHEAST", "EU_CENTRAL"
    QString displayName;           // "Northeastern United States"
    QStringList timezones;         // All valid timezones for region
    QStringList languages;         // Primary languages
    QStringList culturalMarkers;   // Cultural context clues
    double coordinateBounds[4];    // [minLat, maxLat, minLon, maxLon]
    int credibilityWeight;         // Weight for selection probability
};

struct LocationProfile {
    QString locationId;            // Unique identifier
    QString displayName;           // "Boston Financial District"
    QString address;               // Realistic street address
    QString city;                  // City name
    QString state;                 // State/province
    QString postalCode;            // ZIP/postal code
    double latitude;               // GPS coordinates
    double longitude;              // GPS coordinates
    QString timezone;              // IANA timezone
    QStringList businessTypes;     // Realistic business context
    int credibilityScore;          // 1-10 realism rating
    QDateTime lastUsed;            // Rotation tracking
    QString regionId;              // Associated geographic region
    bool isDecoy = false;          // True if generated for counterintelligence

    // Serialization methods
    QByteArray serialize() const;
    static LocationProfile deserialize(const QByteArray &data);

    // Generate location fingerprint for deduplication
    QString generateFingerprint() const;
};

struct RandomizationPolicy {
    enum RotationSchedule {
        PerSession,     // New location each session
        Daily,          // Daily rotation
        Weekly,         // Weekly rotation
        MessageBased    // Rotation based on message count
    };

    RotationSchedule schedule = Daily;
    int maxLocationReuse = 3;      // Max times to reuse location
    int minimumPoolSize = 50;      // Minimum pool size
    bool enforceTimezoneMatch = true;
    bool enforceCulturalMatch = true;
    double noiseRadius = 5.0;      // km radius for coordinate noise
    bool enableDecoyGeneration = true;  // Generate decoy locations
    int decoyRatio = 20;           // Percentage of decoy locations
};

struct PrivacySettings {
    bool enableLocationRandomization = true;
    bool preventLocationTracking = true;
    bool anonymizeTimezones = false;        // True = fake timezone
    bool removeCulturalMarkers = false;     // True = generic locations
    int rotationIntervalHours = 24;
    int maxLocationHistory = 100;
    bool auditModeEnabled = false;          // Logs for privacy audit
    RandomizationPolicy policy;
};

// Phone number analysis and geographic intelligence
class PhoneNumberAnalyzer {
public:
    PhoneNumberAnalyzer();

    // Core analysis methods
    PhoneAnalysis analyzePhoneNumber(const QString &phoneNumber);
    QString extractCountryCode(const QString &phoneNumber);
    QString extractAreaCode(const QString &phoneNumber, const QString &countryCode);
    QStringList getSupportedCountries();

    // Validation and normalization
    bool isValidPhoneNumber(const QString &phoneNumber);
    QString normalizePhoneNumber(const QString &phoneNumber);

private:
    void initializeCountryData();
    void initializeAreaCodeMappings();

    QMap<QString, QString> _countryCodeToRegion;
    QMap<QString, QMap<QString, QString>> _areaCodeToRegion; // [country][areacode] -> region
    QMap<QString, QStringList> _regionToTimezones;
    QMap<QString, QStringList> _regionToCultures;
};

// Geographic mapping and region management
class GeographicMapper {
public:
    GeographicMapper();

    // Core mapping methods
    GeographicRegion mapAreaCodeToRegion(const QString &countryCode,
                                         const QString &areaCode);
    QStringList getCompatibleRegions(const QString &primaryRegion);
    bool areRegionsCompatible(const QString &region1, const QString &region2);

    // Region information
    QVector<GeographicRegion> getAllRegions();
    GeographicRegion getRegion(const QString &regionId);
    QStringList getRegionTimezones(const QString &regionId);

private:
    void initializeRegions();
    void calculateRegionCompatibility();

    QMap<QString, GeographicRegion> _regions;
    QMap<QString, QStringList> _regionCompatibility;
    QMap<QString, QVector<LocationProfile>> _regionLocationSeeds;
};

// Location pool generation and management
class LocationPoolManager {
public:
    LocationPoolManager();

    // Pool generation
    QVector<LocationProfile> generateLocationPool(
        const QString &regionId,
        int poolSize = 100);

    LocationProfile selectRandomLocation(
        const QString &regionId,
        const QStringList &excludeRecent = QStringList());

    // Pool management
    void markLocationUsed(const QString &locationId);
    void rotateLocationPools();
    void clearLocationHistory();

    // Decoy generation for counterintelligence
    QVector<LocationProfile> generateDecoyLocations(
        const QString &regionId,
        int decoyCount = 20);

    // Pool statistics
    int getPoolSize(const QString &regionId);
    int getAvailableLocations(const QString &regionId);
    double getPoolFreshness(const QString &regionId); // 0.0-1.0

private:
    void seedLocationPools();
    LocationProfile generateRealisticLocation(const GeographicRegion &region);
    QString generateRealisticAddress(const GeographicRegion &region);
    QStringList generateBusinessTypes(const GeographicRegion &region);

    QMap<QString, QVector<LocationProfile>> _locationPools;
    QMap<QString, QDateTime> _lastPoolRotation;
    QMap<QString, QStringList> _recentLocationHistory;

    // Business type templates for different regions
    QMap<QString, QStringList> _businessTypeTemplates;
    QMap<QString, QStringList> _addressTemplates;
};

// Smart randomization with privacy protection
class SmartLocationRandomizer {
public:
    SmartLocationRandomizer(LocationPoolManager *poolManager);

    // Core randomization
    LocationProfile selectLocation(
        const PhoneAnalysis &phoneAnalysis,
        const RandomizationPolicy &policy = RandomizationPolicy{});

    // Privacy protection
    void addCoordinateNoise(LocationProfile &location, double radiusKm);
    bool shouldRotateLocation(const QString &currentLocationId,
                              const RandomizationPolicy &policy);
    QStringList getLocationHistory(int maxHistory = 10);

    // Pattern prevention
    void preventPatternAnalysis();
    double calculateSelectionEntropy(); // Measure randomization quality
    bool detectSuspiciousPatterns(); // Detect if patterns are emerging

    // Decoy management
    void injectDecoyLocations(QVector<LocationProfile> &locations, int decoyRatio);
    bool isDecoyLocation(const QString &locationId);

private:
    LocationPoolManager *_poolManager;
    QStringList _locationHistory;
    QMap<QString, int> _locationUsageCount;
    QMap<QString, QDateTime> _lastRotationTime;

    // Pattern analysis data
    QVector<double> _selectionEntropy;
    QVector<QPair<QDateTime, QString>> _selectionPattern;

    // Cryptographically secure random number generation
    uint32_t generateSecureRandom(uint32_t min, uint32_t max);
    double generateSecureRandomDouble();
};

// Master location randomization manager
class LocationRandomizationManager : public QObject {
    Q_OBJECT

public:
    LocationRandomizationManager(QObject *parent = nullptr);
    ~LocationRandomizationManager();

    // Initialization and configuration
    void initialize(const PrivacySettings &settings);
    void updateSettings(const PrivacySettings &settings);
    PrivacySettings currentSettings() const;

    // Core interface
    LocationProfile getCurrentLocation();
    void setUserPhoneNumber(const QString &phoneNumber);
    void forceLocationRotation();
    void clearLocationHistory();

    // Privacy protection
    void preventPatternAnalysis();
    void removeTrackingMarkers();
    QStringList getPrivacyAuditLog();
    bool detectPrivacyThreats();

    // Integration with counterintelligence
    void integrateWithHoneypotSystem(CounterIntelligenceManager *ci);
    void generateDecoyLocationTrail();
    QVariantMap generateEnhancedHoneypotLocation(const QString &context = QString());

    // Status and monitoring
    bool isLocationRandomizationActive();
    QString getSystemStatus();
    QVariantMap getSystemMetrics();

Q_SIGNALS:
    void locationRotated(const LocationProfile &newLocation);
    void privacyThreatDetected(const QString &threatDescription);
    void auditLogUpdated();
    void decoyLocationGenerated(const LocationProfile &decoyLocation);

private Q_SLOTS:
    void onRotationTimerTriggered();
    void onMessageCountChanged(int messageCount);

private:
    // Component instances
    std::unique_ptr<PhoneNumberAnalyzer> _phoneAnalyzer;
    std::unique_ptr<GeographicMapper> _geoMapper;
    std::unique_ptr<LocationPoolManager> _poolManager;
    std::unique_ptr<SmartLocationRandomizer> _randomizer;

    // Integration
    CounterIntelligenceManager *_counterIntelManager = nullptr;

    // Current state
    PrivacySettings _settings;
    LocationProfile _currentLocation;
    PhoneAnalysis _userPhoneAnalysis;
    QTimer *_rotationTimer = nullptr;

    // Privacy protection
    QStringList _auditLog;
    QDateTime _lastThreatCheck;
    QMap<QString, QDateTime> _threatHistory;

    // Statistics
    int _rotationCount = 0;
    int _decoyCount = 0;
    QDateTime _initialized;

    // Methods
    void setupRotationTimer();
    void performLocationRotation();
    void updateAuditLog(const QString &event);
    void checkForPrivacyThreats();
    bool validateLocationCredibility(const LocationProfile &location);

    // Enhanced honeypot integration
    void enhanceHoneypotLocation(QVariantMap &honeypotData);
    LocationProfile generateContextualDecoy(const QString &context);
};

} // namespace Data