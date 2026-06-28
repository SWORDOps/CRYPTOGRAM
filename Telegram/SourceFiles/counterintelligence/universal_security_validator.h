#pragma once

// Universal Security Validator - Ensures Minimum Security Guarantees Across All Hardware Tiers
// PATCHER AGENT: Critical Security Implementation for Phase 4 Counterintelligence
// Addresses VULN-TIER-001, VULN-TIER-002 from DEBUGGER analysis

#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QMutex>
#include "../counterintelligence/surveillance_detector.h"

namespace SpyGram::Counterintelligence {

// Universal security baseline configuration
struct SecurityBaseline {
    float minimum_confidence_threshold = 0.3f;  // Minimum acceptable confidence
    int minimum_threat_detection_level = 1;     // Minimum threat level detection
    bool require_multiple_validation = true;    // Require multiple validation methods
    bool enable_cross_tier_verification = true; // Enable cross-tier result verification
    int maximum_false_positive_rate = 20;       // Maximum 20% false positive rate
    int minimum_true_positive_rate = 70;        // Minimum 70% true positive rate
};

// Hardware tier classification
enum class SecurityTier {
    Tier0_Quantum = 0,      // GNA + NPU + TPM 2.0
    Tier1_Premium = 1,      // NPU + TPM 2.0 + OpenVINO
    Tier2_Enhanced = 2,     // TPM 2.0 + OpenVINO + CPU
    Tier3_Standard = 3,     // CPU + Software TSM
    Tier4_Universal = 4     // CPU + Basic storage
};

// Security validation result
struct SecurityValidationResult {
    bool meets_baseline = false;
    SecurityTier effective_tier = SecurityTier::Tier4_Universal;
    float confidence_adjustment = 0.0f;
    QString validation_details;
    QStringList security_guarantees;
    QStringList limitations;
    int validation_methods_used = 0;
};

class UniversalSecurityValidator : public QObject {
    Q_OBJECT

public:
    explicit UniversalSecurityValidator(QObject *parent = nullptr);
    ~UniversalSecurityValidator();

    // Security baseline management
    void setSecurityBaseline(const SecurityBaseline &baseline);
    SecurityBaseline getSecurityBaseline() const;

    // Hardware tier detection and validation
    SecurityTier detectHardwareTier();
    SecurityValidationResult validateSecurityCapabilities(SecurityTier tier);

    // Universal threat assessment validation
    ThreatAssessment validateThreatAssessment(const ThreatAssessment &threat, SecurityTier tier);
    ThreatAssessment ensureMinimumSecurity(const ThreatAssessment &threat);

    // Cross-tier verification
    ThreatAssessment performCrossTierValidation(const ThreatAssessment &primary,
                                               const ThreatAssessment &secondary);

    // Security guarantee validation
    bool validateSecurityGuarantees(SecurityTier tier);
    QStringList getSecurityGuarantees(SecurityTier tier) const;

    // Performance vs security optimization
    ThreatAssessment optimizeForSecurity(const ThreatAssessment &threat, SecurityTier tier);
    float calculateSecurityScore(const ThreatAssessment &threat, SecurityTier tier);

    // Tier-specific enhancements
    ThreatAssessment enhanceTier4Security(const ThreatAssessment &threat);
    ThreatAssessment enhanceTier3Security(const ThreatAssessment &threat);
    ThreatAssessment enhanceTier2Security(const ThreatAssessment &threat);

    // Security monitoring
    void enableUniversalSecurityLogging(bool enable);
    QStringList getSecurityValidationLogs() const;

Q_SIGNALS:
    void securityBaselineViolation(const QString &violation);
    void tierValidationFailed(SecurityTier tier, const QString &reason);
    void crossTierDiscrepancy(const ThreatAssessment &primary, const ThreatAssessment &secondary);

private:
    // Hardware capability detection
    bool detectGNACapability();
    bool detectNPUCapability();
    bool detectTPMCapability();
    bool detectOpenVINOCapability();
    bool detectAdvancedCPUFeatures();

    // Security validation implementation
    ThreatAssessment validateWithMultipleMethods(const ThreatAssessment &threat, SecurityTier tier);
    bool performConfidenceValidation(const ThreatAssessment &threat);
    bool performConsistencyValidation(const ThreatAssessment &threat, SecurityTier tier);

    // Tier-specific security implementations
    ThreatAssessment applyTier4SecurityEnhancements(const ThreatAssessment &threat);
    ThreatAssessment applyTier3SecurityEnhancements(const ThreatAssessment &threat);
    ThreatAssessment applyUniversalSecurityFilters(const ThreatAssessment &threat);

    // Security baseline enforcement
    ThreatAssessment enforceMinimumConfidence(const ThreatAssessment &threat);
    ThreatAssessment enforceMinimumThreatLevel(const ThreatAssessment &threat);
    ThreatAssessment enforceUniversalValidation(const ThreatAssessment &threat);

    // Alternative detection methods for lower tiers
    ThreatAssessment performSignatureBasedDetection(const QByteArray &audioData);
    ThreatAssessment performPatternBasedDetection(const QByteArray &audioData);
    ThreatAssessment performStatisticalDetection(const QByteArray &audioData);
    ThreatAssessment performRuleBasedDetection(const QByteArray &audioData);

    // Security logging
    void logSecurityValidation(const QString &event, const QString &details);

private:
    SecurityBaseline _baseline;
    SecurityTier _current_tier;
    mutable QMutex _validation_mutex;
    bool _security_logging_enabled = true;
    QStringList _validation_logs;

    // Hardware capability cache
    bool _gna_available = false;
    bool _npu_available = false;
    bool _tpm_available = false;
    bool _openvino_available = false;
    bool _advanced_cpu_features = false;

    // Validation statistics
    qint64 _validations_performed = 0;
    qint64 _baseline_violations = 0;
    qint64 _tier_upgrades = 0;
    qint64 _cross_tier_discrepancies = 0;

    // Security constants
    static constexpr float UNIVERSAL_MINIMUM_CONFIDENCE = 0.3f;
    static constexpr float TIER_CONFIDENCE_BOOST = 0.1f;
    static constexpr int MAX_VALIDATION_METHODS = 5;
    static constexpr int VALIDATION_LOG_LIMIT = 500;
};

} // namespace SpyGram::Counterintelligence