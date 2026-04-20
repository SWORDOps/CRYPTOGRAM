/*
This file is part of SpyGram Desktop,
the privacy-enhanced desktop application for secure messaging.

For license and copyright information please follow this link:
https://github.com/SWORDIntel/SpyGram/blob/main/LEGAL
*/
#pragma once

#include "base/bytes.h"
#include "base/expected.h"
#include "data/data_quantumguard.h"
#include "data/data_nsa_security.h"
#include "data/data_quantum_types.h"

#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QDateTime>
#include <memory>
#include <map>
#include <functional>

namespace Data {

// Cryptographic operation types
enum class CryptoOperation {
    KeyGeneration,
    Encryption,
    Decryption,
    Signing,
    Verification,
    KeyAgreement,
    KeyDerivation,
    RandomGeneration,
    Hashing
};

// Hardware acceleration types
enum class AccelerationType {
    None,               // Pure software implementation
    CPU_AES_NI,        // CPU AES-NI instructions
    CPU_AVX2,          // CPU AVX2 SIMD instructions
    CPU_AVX512,        // CPU AVX-512 instructions
    GPU_OpenCL,        // GPU acceleration via OpenCL
    NPU_OpenVINO,      // NPU acceleration via OpenVINO
    GNA_Quantum,       // GNA quantum acceleration
    TPM_Hardware,      // TPM hardware acceleration
    HSM_Hardware       // Hardware Security Module
};

// Performance requirements
enum class PerformanceClass {
    Basic,             // <1000ms acceptable
    Standard,          // <100ms required
    Enhanced,          // <10ms required
    RealTime,          // <1ms required
    UltraLow          // <0.1ms required
};

// Security strength levels
enum class SecurityStrength {
    Level128 = 128,    // 128-bit classical security
    Level192 = 192,    // 192-bit classical security
    Level256 = 256,    // 256-bit classical security
    Level384 = 384,    // 384-bit classical security
    Level512 = 512     // 512-bit classical security
};

// Cryptographic operation result
struct CryptoOperationResult {
    bool success;
    bytes::vector result;
    QString errorMessage;
    AccelerationType accelerationUsed;
    double executionTimeMs;
    SecurityStrength achievedSecurity;
    QuantumAlgorithm quantumAlgorithm;
    bool isQuantumResistant;
};

// Hardware capability information
struct HardwareCapability {
    AccelerationType type;
    QString description;
    bool available;
    bool tested;
    double performanceFactor; // Relative to baseline CPU
    QStringList supportedAlgorithms;
    SecurityStrength maxSecurityLevel;
    QString vendorInfo;
    QString driverVersion;
};

// Cryptographic algorithm performance profile
struct AlgorithmProfile {
    QString algorithmName;
    CryptoOperation operationType;
    SecurityStrength securityLevel;
    bool isQuantumResistant;

    // Performance by acceleration type
    std::map<AccelerationType, double> performanceMs;

    // Hardware requirements
    QStringList requiredFeatures;
    size_t minimumMemoryMB;
    bool requiresSpecializedHardware;

    // Implementation status
    bool implemented;
    QString implementationNotes;
};

// Quantum cryptographic services with hardware acceleration
class QuantumCryptoServices : public QObject {
    Q_OBJECT

public:
    explicit QuantumCryptoServices(QObject *parent = nullptr);
    ~QuantumCryptoServices();

    // Initialization and configuration
    bool initialize();
    bool isInitialized() const;

    // Hardware detection and configuration
    bool detectHardwareCapabilities();
    QList<HardwareCapability> getAvailableHardware() const;
    bool enableHardwareAcceleration(AccelerationType type, bool enabled = true);
    bool isHardwareAccelerationEnabled(AccelerationType type) const;
    AccelerationType getOptimalAcceleration(CryptoOperation operation,
                                          PerformanceClass performanceClass) const;

    // Algorithm selection and optimization
    QuantumAlgorithm selectOptimalAlgorithm(CryptoOperation operation,
                                          SecurityStrength minSecurity,
                                          PerformanceClass performanceClass) const;

    QList<QuantumAlgorithm> getSupportedAlgorithms(CryptoOperation operation) const;
    AlgorithmProfile getAlgorithmProfile(QuantumAlgorithm algorithm,
                                       CryptoOperation operation) const;

    // Quantum-resistant key generation (NIST FIPS 203 Standard)
    base::expected<CryptoOperationResult, QString> generateQuantumKey(
        QuantumKeyType keyType,
        QuantumAlgorithm algorithm = QuantumAlgorithm::ML_KEM_1024,  // NIST standard default
        AccelerationType preferredAcceleration = AccelerationType::None);

    base::expected<CryptoOperationResult, QString> generateHybridKey(
        QuantumKeyType keyType,
        QuantumAlgorithm quantumAlgorithm,
        const QString &classicalAlgorithm = "X25519");  // Updated to X25519 for key exchange

    // Quantum-resistant encryption/decryption (NIST FIPS 203 Standard)
    base::expected<CryptoOperationResult, QString> quantumEncrypt(
        const bytes::const_span &plaintext,
        const bytes::const_span &publicKey,
        QuantumAlgorithm algorithm = QuantumAlgorithm::ML_KEM_1024,  // NIST standard default
        AccelerationType preferredAcceleration = AccelerationType::None);

    base::expected<CryptoOperationResult, QString> quantumDecrypt(
        const bytes::const_span &ciphertext,
        const bytes::const_span &privateKey,
        QuantumAlgorithm algorithm = QuantumAlgorithm::ML_KEM_1024,  // NIST standard default
        AccelerationType preferredAcceleration = AccelerationType::None);

    base::expected<CryptoOperationResult, QString> hybridEncrypt(
        const bytes::const_span &plaintext,
        const bytes::const_span &quantumPublicKey,
        const bytes::const_span &classicalPublicKey,
        QuantumAlgorithm quantumAlgorithm = QuantumAlgorithm::HybridX25519_ML_KEM_1024);  // Hybrid default

    base::expected<CryptoOperationResult, QString> hybridDecrypt(
        const bytes::const_span &ciphertext,
        const bytes::const_span &quantumPrivateKey,
        const bytes::const_span &classicalPrivateKey,
        QuantumAlgorithm quantumAlgorithm = QuantumAlgorithm::HybridX25519_ML_KEM_1024);  // Hybrid default

    // Quantum-resistant digital signatures (NIST FIPS 204 Standard)
    base::expected<CryptoOperationResult, QString> quantumSign(
        const bytes::const_span &message,
        const bytes::const_span &privateKey,
        QuantumAlgorithm algorithm = QuantumAlgorithm::ML_DSA_87,  // NIST standard default
        AccelerationType preferredAcceleration = AccelerationType::None);

    base::expected<CryptoOperationResult, QString> quantumVerify(
        const bytes::const_span &message,
        const bytes::const_span &signature,
        const bytes::const_span &publicKey,
        QuantumAlgorithm algorithm = QuantumAlgorithm::ML_DSA_87,  // NIST standard default
        AccelerationType preferredAcceleration = AccelerationType::None);

    // Quantum-safe key agreement (NIST FIPS 203 Standard)
    base::expected<CryptoOperationResult, QString> quantumKeyAgreement(
        const bytes::const_span &localPrivateKey,
        const bytes::const_span &remotePublicKey,
        QuantumAlgorithm algorithm = QuantumAlgorithm::ML_KEM_1024,  // NIST standard default
        AccelerationType preferredAcceleration = AccelerationType::None);

    // Quantum-safe key derivation
    base::expected<CryptoOperationResult, QString> quantumKeyDerivation(
        const bytes::const_span &inputKeyMaterial,
        const QString &info,
        size_t outputLength,
        const QString &hashAlgorithm = "SHA3-256",
        AccelerationType preferredAcceleration = AccelerationType::None);

    // Quantum-safe random number generation
    base::expected<CryptoOperationResult, QString> quantumRandomGeneration(
        size_t length,
        AccelerationType preferredAcceleration = AccelerationType::None);

    // Quantum-safe hashing
    base::expected<CryptoOperationResult, QString> quantumHash(
        const bytes::const_span &data,
        const QString &algorithm = "SHA3-256",
        AccelerationType preferredAcceleration = AccelerationType::None);

    // Performance optimization
    void enableAdaptiveAcceleration(bool enabled);
    bool isAdaptiveAccelerationEnabled() const;

    void setBenchmarkingEnabled(bool enabled);
    bool isBenchmarkingEnabled() const;

    void performBenchmarks();
    QMap<QString, double> getBenchmarkResults() const;


        AccelerationType preferredAcceleration = AccelerationType::TPM_Hardware);

        const bytes::const_span &plaintext,
        const QString &keyId,
        AccelerationType preferredAcceleration = AccelerationType::TPM_Hardware);

        const bytes::const_span &ciphertext,
        const QString &keyId,
        AccelerationType preferredAcceleration = AccelerationType::TPM_Hardware);

        const bytes::const_span &data,
        const QString &keyId,
        AccelerationType preferredAcceleration = AccelerationType::TPM_Hardware);

        const bytes::const_span &nonce,
        AccelerationType preferredAcceleration = AccelerationType::TPM_Hardware);

    // NSA-grade security features
    void setNSASecurity(std::shared_ptr<NSASecurity> nsaSecurity);
    void enableNSAGradeSecurity(bool enabled);
    bool isNSAGradeSecurityEnabled() const;

    void setClassificationLevel(NSAClassificationLevel level);
    NSAClassificationLevel getCurrentClassificationLevel() const;

    // Emergency and threat response
    void enableQuantumThreatMode();
    void disableClassicalCrypto();
    void enableEmergencyMode();

    // Performance monitoring
    struct CryptoPerformanceMetrics {
        uint64 totalOperations = 0;
        uint64 quantumOperations = 0;
        uint64 hardwareAcceleratedOps = 0;
        uint64 softwareOnlyOps = 0;

        double averageOperationTime = 0.0;
        double hardwareAccelerationRatio = 0.0;
        double quantumResistantRatio = 0.0;

        QString fastestAccelerationType;
        QString mostSecureAlgorithm;
        QString mostUsedAlgorithm;

        std::map<AccelerationType, uint64> accelerationUsage;
        std::map<QuantumAlgorithm, uint64> algorithmUsage;
        std::map<CryptoOperation, double> operationTimes;

        QDateTime lastOperation;
        uint64 operationsPerSecond = 0;
        double averageThroughputMBps = 0.0;
    };

    CryptoPerformanceMetrics getPerformanceMetrics() const;
    void resetPerformanceMetrics();

    // System diagnostics
    bool runSelfTest();
    QStringList getSelfTestResults() const;

    bool validateHardwareIntegrity();
    QStringList getIntegrityCheckResults() const;

signals:
    void hardwareCapabilityChanged(AccelerationType type, bool available);
    void algorithmBenchmarkCompleted(QuantumAlgorithm algorithm, double performanceMs);
    void quantumThreatDetected();
    void nsaSecurityEventDetected(const QString &event);
    void performanceThresholdExceeded(CryptoOperation operation, double actualTimeMs);
    void hardwareAccelerationFailed(AccelerationType type, const QString &error);

private:
    // Core implementation
    class QuantumCryptoServicesPrivate;
    std::unique_ptr<QuantumCryptoServicesPrivate> d;

    // Hardware-specific implementations
    CryptoOperationResult performCPUOperation(CryptoOperation operation,
                                            const bytes::const_span &input,
                                            QuantumAlgorithm algorithm);

    CryptoOperationResult performGPUOperation(CryptoOperation operation,
                                            const bytes::const_span &input,
                                            QuantumAlgorithm algorithm);

    CryptoOperationResult performNPUOperation(CryptoOperation operation,
                                            const bytes::const_span &input,
                                            QuantumAlgorithm algorithm);

    CryptoOperationResult performGNAOperation(CryptoOperation operation,
                                            const bytes::const_span &input,
                                            QuantumAlgorithm algorithm);

    CryptoOperationResult performTPMOperation(CryptoOperation operation,
                                            const bytes::const_span &input,
                                            const QString &keyId);

    // Algorithm implementations
    CryptoOperationResult implementKyber(CryptoOperation operation,
                                       const bytes::const_span &input,
                                       int securityLevel,
                                       AccelerationType acceleration);

    CryptoOperationResult implementDilithium(CryptoOperation operation,
                                            const bytes::const_span &input,
                                            int securityLevel,
                                            AccelerationType acceleration);

    CryptoOperationResult implementSPHINCS(CryptoOperation operation,
                                          const bytes::const_span &input,
                                          bool useSHA256,
                                          AccelerationType acceleration);

    // Performance optimization
    void updatePerformanceMetrics(CryptoOperation operation,
                                AccelerationType acceleration,
                                double executionTime,
                                bool success);

    AccelerationType selectOptimalAccelerationForOperation(
        CryptoOperation operation,
        QuantumAlgorithm algorithm,
        PerformanceClass targetPerformance) const;

    void adaptAccelerationStrategy();
    bool shouldUseHardwareAcceleration(CryptoOperation operation,
                                     AccelerationType type) const;

    // Security validation
    bool validateQuantumSecurity(QuantumAlgorithm algorithm) const;
    bool validateNSACompliance(CryptoOperation operation,
                             QuantumAlgorithm algorithm) const;
    void auditCryptoOperation(CryptoOperation operation,
                            QuantumAlgorithm algorithm,
                            bool success,
                            double executionTime);

    // State management
    bool _initialized = false;
    bool _adaptiveAcceleration = true;
    bool _benchmarkingEnabled = false;
    bool _nsaGradeSecurity = false;
    bool _quantumThreatMode = false;
    bool _emergencyMode = false;

    NSAClassificationLevel _classificationLevel = NSAClassificationLevel::Secret;
    mutable CryptoPerformanceMetrics _performanceMetrics;

    std::shared_ptr<NSASecurity> _nsaSecurity;
    std::shared_ptr<QuantumGuard> _quantumGuard;

    std::map<AccelerationType, bool> _enabledAccelerations;
    std::map<QuantumAlgorithm, AlgorithmProfile> _algorithmProfiles;
    std::vector<HardwareCapability> _hardwareCapabilities;
};

// Factory for creating optimized crypto services
class QuantumCryptoServicesFactory {
public:
    // Create optimized instance for current hardware
    static std::unique_ptr<QuantumCryptoServices> createOptimized();

    // Create with specific acceleration requirements
    static std::unique_ptr<QuantumCryptoServices> createWithAcceleration(
        const QList<AccelerationType> &preferredTypes);

    // Create for specific performance class
    static std::unique_ptr<QuantumCryptoServices> createForPerformance(
        PerformanceClass targetPerformance);

    // Create with security requirements
    static std::unique_ptr<QuantumCryptoServices> createForSecurity(
        SecurityStrength minSecurity,
        bool requireQuantumResistance = true);


    // Hardware capability detection
    static QList<HardwareCapability> detectHardwareCapabilities();
    static bool isQuantumAccelerationAvailable();
    static AccelerationType getRecommendedAcceleration();

    // Universal Accessibility support
    static QuantumCryptoServices* createUniversalInstance();
    static void configureUniversalFallbacks(QuantumCryptoServices* services);
};

} // namespace Data