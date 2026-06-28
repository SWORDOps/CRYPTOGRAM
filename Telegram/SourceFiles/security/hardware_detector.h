/*
This file is part of SpyGram Desktop,
the privacy-enhanced desktop application for secure messaging.

For license and copyright information please follow this link:
https://github.com/SWORDIntel/SpyGram/blob/main/LEGAL
*/
#pragma once

#include "base/bytes.h"
#include "base/expected.h"

#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QTimer>
#include <QtCore/QThread>
#include <QtCore/QMutex>
#include <memory>
#include <vector>

namespace Security {

// Hardware detection result types
enum class HardwareDetectionResult {
    Success,
    NotAvailable,
    PermissionDenied,
    DriverMissing,
    VersionMismatch,
    TestFailed,
    UnknownError
};

// NPU (Neural Processing Unit) information
struct NPUInfo {
    bool available = false;
    QString name;
    QString driver;
    QString version;
    int computeUnits = 0;
    double maxTOPS = 0.0;          // Tera Operations Per Second
    bool openvinoSupport = false;
    QString deviceId;
    QString vendorId;
    double powerConsumption = 0.0;  // Watts
    QStringList supportedFormats;  // Supported model formats
};

// TPM (Trusted Platform Module) information
struct TPMInfo {
    bool available = false;
    QString version;               // "2.0", "1.2", etc.
    QString manufacturer;
    QString firmwareVersion;
    QString devicePath;            // /dev/tpm0, etc.
    bool fipsCompliant = false;
    QStringList algorithms;        // Supported crypto algorithms
    int keySlots = 0;             // Available key storage slots
    bool attestationSupport = false;
    QString spec;                 // TPM specification version
};

// OpenVINO Runtime information
struct OpenVINOInfo {
    bool available = false;
    QString version;
    QString installPath;
    QStringList availableDevices;  // CPU, GPU, NPU, etc.
    QStringList supportedFormats;  // ONNX, IR, etc.
    bool optimizationsEnabled = false;
    QString runtimeVersion;
    QStringList pluginVersions;
};

// CPU capabilities relevant to security
struct CPUInfo {
    QString name;
    QString architecture;
    int cores = 0;
    int threads = 0;
    QStringList features;          // AVX, AES-NI, etc.
    bool aesniSupport = false;
    bool avxSupport = false;
    bool avx512Support = false;
    double frequency = 0.0;        // GHz
    int cacheSize = 0;            // KB
    QString vendor;
};

// GPU information for compute acceleration
struct GPUInfo {
    bool available = false;
    QString name;
    QString vendor;
    QString driver;
    int computeUnits = 0;
    size_t memory = 0;            // MB
    bool openclSupport = false;
    bool vulkanSupport = false;
    QString deviceId;
};

// Complete hardware profile
struct HardwareProfile {
    NPUInfo npu;
    TPMInfo tpm;
    OpenVINOInfo openvino;
    CPUInfo cpu;
    GPUInfo gpu;
    QDateTime detectionTime;
    QString systemInfo;           // OS, kernel version, etc.
    double overallScore = 0.0;    // 0-100 composite capability score
};

// Performance benchmark results
struct BenchmarkResults {
    struct CryptoTest {
        double aes256Throughput = 0.0;    // MB/s
        double sha256Throughput = 0.0;    // MB/s
        double ed25519SignLatency = 0.0;  // ms
        double x25519DhLatency = 0.0;     // ms
    };

    struct AITest {
        double inferenceLatency = 0.0;    // ms
        double throughput = 0.0;          // inferences/sec
        double accuracy = 0.0;            // 0-1
        QString modelUsed;
    };

    CryptoTest crypto;
    AITest ai;
    double memoryBandwidth = 0.0;         // MB/s
    double diskIOLatency = 0.0;           // ms
    QDateTime benchmarkTime;
    QString hardwareUsed;                 // Which hardware was used for test
};

// Hardware detector main class
class HardwareDetector : public QObject {
    Q_OBJECT

public:
    explicit HardwareDetector(QObject *parent = nullptr);
    ~HardwareDetector();

    // Detection methods
    void detectAll();
    void detectNPU();
    void detectTPM();
    void detectOpenVINO();
    void detectCPU();
    void detectGPU();

    // Results retrieval
    HardwareProfile getHardwareProfile() const;
    NPUInfo getNPUInfo() const;
    TPMInfo getTPMInfo() const;
    OpenVINOInfo getOpenVINOInfo() const;
    CPUInfo getCPUInfo() const;
    GPUInfo getGPUInfo() const;

    // Availability checks
    bool isNPUAvailable() const;
    bool isTPMAvailable() const;
    bool isOpenVINOAvailable() const;
    bool hasHardwareAcceleration() const;
    bool hasSecureHardware() const;

    // Performance testing
    void runBenchmarks();
    BenchmarkResults getBenchmarkResults() const;
    double calculateOverallScore() const;
    QString getPerformanceReport() const;

    // Specific hardware tests
    bool testNPUPerformance();
    bool testTPMOperations();
    bool testOpenVINOInference();
    bool testCryptographicAcceleration();

    // Configuration and optimization
    QStringList getOptimalDeviceOrder() const;
    QString getBestAIDevice() const;
    QString getBestCryptoDevice() const;
    void optimizeForSecurity();
    void optimizeForPerformance();

    // Monitoring and updates
    void startContinuousMonitoring(int intervalMs = 30000);
    void stopContinuousMonitoring();
    bool isContinuousMonitoringActive() const;
    void refreshHardwareStatus();

    // Hardware-specific operations
    base::expected<QStringList, HardwareDetectionResult> getNPUDeviceList();
    base::expected<QString, HardwareDetectionResult> getTPMDevicePath();
    base::expected<QStringList, HardwareDetectionResult> getOpenVINODevices();

    // System information
    QString getSystemInfo() const;
    QString getKernelVersion() const;
    QString getDistribution() const;
    QStringList getLoadedDrivers() const;

Q_SIGNALS:
    void detectionComplete(const HardwareProfile &profile);
    void npuDetected(const NPUInfo &info);
    void tpmDetected(const TPMInfo &info);
    void openvinoDetected(const OpenVINOInfo &info);
    void benchmarkComplete(const BenchmarkResults &results);
    void hardwareStatusChanged(const QString &component, bool available);
    void detectionError(const QString &component, HardwareDetectionResult error);

private Q_SLOTS:
    void onDetectionFinished();
    void onBenchmarkFinished();
    void onMonitoringTimer();

private:
    // Detection implementations
    NPUInfo detectNPUInternal();
    TPMInfo detectTPMInternal();
    OpenVINOInfo detectOpenVINOInternal();
    CPUInfo detectCPUInternal();
    GPUInfo detectGPUInternal();

    // Platform-specific detection
    NPUInfo detectIntelNPU();
    NPUInfo detectAMDNPU();
    NPUInfo detectNVIDIANPU();
    TPMInfo detectLinuxTPM();
    TPMInfo detectWindowsTPM();
    TPMInfo detectMacTPM();

    // OpenVINO detection methods
    bool detectOpenVINOInstallation();
    QStringList detectOpenVINODevices();
    QString getOpenVINOVersion();
    bool testOpenVINODevice(const QString &device);

    // CPU feature detection
    bool detectCPUFeature(const QString &feature);
    QStringList getCPUFlags();
    double getCPUFrequency();
    int getCPUCacheSize();

    // GPU detection methods
    GPUInfo detectIntelGPU();
    GPUInfo detectAMDGPU();
    GPUInfo detectNVIDIAGPU();
    bool testGPUCompute(const QString &device);

    // Benchmark implementations
    BenchmarkResults::CryptoTest runCryptoBenchmark();
    BenchmarkResults::AITest runAIBenchmark();
    double measureMemoryBandwidth();
    double measureDiskIOLatency();

    // Hardware testing utilities
    bool testDevice(const QString &devicePath);
    bool loadKernelModule(const QString &moduleName);
    QString executeCommand(const QString &command);
    QStringList parseCommandOutput(const QString &output);

    // Score calculation
    double calculateNPUScore(const NPUInfo &npu) const;
    double calculateTPMScore(const TPMInfo &tpm) const;
    double calculateCPUScore(const CPUInfo &cpu) const;
    double calculateGPUScore(const GPUInfo &gpu) const;

    // State management
    mutable QMutex _mutex;
    HardwareProfile _profile;
    BenchmarkResults _benchmarkResults;
    bool _detectionComplete = false;
    bool _benchmarkComplete = false;

    // Monitoring
    std::unique_ptr<QTimer> _monitoringTimer;
    bool _continuousMonitoring = false;

    // Detection worker thread
    QThread *_detectionThread = nullptr;

    // Cache for repeated operations
    QStringList _cachedNPUDevices;
    QString _cachedTPMPath;
    QStringList _cachedOpenVINODevices;
    QDateTime _cacheTime;
    static constexpr int CacheValidityMs = 60000; // 1 minute

    // Helper methods
    void updateHardwareProfile();
    void clearCache();
    bool isCacheValid() const;
    void logDetectionResult(const QString &component, HardwareDetectionResult result);
    QString formatHardwareInfo(const HardwareProfile &profile) const;
    void validateDetectionResults();
    bool checkPermissions(const QString &devicePath);
    void setupSignalConnections();
};

// Hardware detection utilities
namespace HardwareUtils {
    QString hardwareDetectionResultToString(HardwareDetectionResult result);
    bool isHardwareSecurityCapable(const HardwareProfile &profile);
    bool isAIAccelerationCapable(const HardwareProfile &profile);
    QString formatHardwareProfile(const HardwareProfile &profile);
    QString formatBenchmarkResults(const BenchmarkResults &results);
    QStringList getRequiredKernelModules();
    bool checkSystemRequirements();
    QString getHardwareRecommendations(const HardwareProfile &profile);
}

} // namespace Security