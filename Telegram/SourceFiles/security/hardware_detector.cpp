/*
This file is part of SpyGram Desktop,
the privacy-enhanced desktop application for secure messaging.

For license and copyright information please follow this link:
https://github.com/SWORDIntel/SpyGram/blob/main/LEGAL
*/
#include "security/hardware_detector.h"

#include <QtCore/QProcess>
#include <QtCore/QFile>
#include <QtCore/QDir>
#include <QtCore/QDebug>
#include <QtCore/QThread>
#include <QtCore/QCoreApplication>
#include <QtCore/QStandardPaths>
#include <QtCore/QRegularExpression>

#ifdef Q_OS_LINUX
#include <sys/utsname.h>
#include <unistd.h>
#endif

namespace Security {

HardwareDetector::HardwareDetector(QObject *parent)
    : QObject(parent) {

    // Initialize monitoring timer
    _monitoringTimer = std::make_unique<QTimer>(this);
    connect(_monitoringTimer.get(), &QTimer::timeout, this, &HardwareDetector::onMonitoringTimer);

    // Initialize cache
    _cacheTime = QDateTime::currentDateTime().addSecs(-CacheValidityMs / 1000);
}

HardwareDetector::~HardwareDetector() {
    stopContinuousMonitoring();
}

void HardwareDetector::detectAll() {
    qDebug() << "Starting comprehensive hardware detection...";

    QMutexLocker locker(&_mutex);

    // Clear previous results
    _profile = HardwareProfile();
    _detectionComplete = false;

    // Detect all hardware components
    _profile.npu = detectNPUInternal();
    _profile.tpm = detectTPMInternal();
    _profile.openvino = detectOpenVINOInternal();
    _profile.cpu = detectCPUInternal();
    _profile.gpu = detectGPUInternal();

    // Set detection metadata
    _profile.detectionTime = QDateTime::currentDateTime();
    _profile.systemInfo = getSystemInfo();
    _profile.overallScore = calculateOverallScore();

    _detectionComplete = true;

    qDebug() << "Hardware detection complete. Overall score:" << _profile.overallScore;

    Q_EMIT detectionComplete(_profile);
    Q_EMIT npuDetected(_profile.npu);
    Q_EMIT tpmDetected(_profile.tpm);
    Q_EMIT openvinoDetected(_profile.openvino);
}

NPUInfo HardwareDetector::detectNPUInternal() {
    NPUInfo npu;

    // Try Intel NPU first
    auto intelNPU = detectIntelNPU();
    if (intelNPU.available) {
        return intelNPU;
    }

    // Try AMD NPU
    auto amdNPU = detectAMDNPU();
    if (amdNPU.available) {
        return amdNPU;
    }

    // Try NVIDIA NPU
    auto nvidiaNPU = detectNVIDIANPU();
    if (nvidiaNPU.available) {
        return nvidiaNPU;
    }

    return npu; // Not available
}

NPUInfo HardwareDetector::detectIntelNPU() {
    NPUInfo npu;

    // Check for Intel NPU device files
    QStringList npuDevices = {"/dev/accel/accel0", "/dev/intel_vpu"};

    for (const QString &device : npuDevices) {
        if (QFile::exists(device)) {
            npu.available = true;
            npu.deviceId = device;
            npu.name = "Intel NPU";
            break;
        }
    }

    if (!npu.available) {
        // Check via lspci
        QString lspciOutput = executeCommand("lspci -nn | grep -i 'neural\\|npu\\|ai'");
        if (!lspciOutput.isEmpty()) {
            npu.available = true;
            npu.name = "Intel NPU (PCI)";
            npu.deviceId = "pci";
        }
    }

    if (npu.available) {
        // Get driver information
        QString driverInfo = executeCommand("lsmod | grep intel_vpu");
        if (!driverInfo.isEmpty()) {
            npu.driver = "intel_vpu";
        }

        // Try to get capabilities from sysfs
        QFile capFile("/sys/class/accel/accel0/device/caps");
        if (capFile.open(QIODevice::ReadOnly)) {
            QString caps = capFile.readAll();
            if (caps.contains("inference")) {
                npu.maxTOPS = 11.0; // Intel Meteor Lake NPU typical performance
                npu.powerConsumption = 2.5; // Typical power consumption
            }
        }

        // Check OpenVINO support
        npu.openvinoSupport = testOpenVINODevice("NPU");
        npu.supportedFormats = {"ONNX", "OpenVINO IR", "TensorFlow Lite"};

        qDebug() << "Intel NPU detected:" << npu.name << "at" << npu.deviceId;
    }

    return npu;
}

NPUInfo HardwareDetector::detectAMDNPU() {
    NPUInfo npu;

    // Check for AMD AI accelerator devices
    QString lspciOutput = executeCommand("lspci -nn | grep -i 'amd.*ai\\|amd.*npu'");
    if (!lspciOutput.isEmpty()) {
        npu.available = true;
        npu.name = "AMD NPU";
        npu.deviceId = "pci_amd";
        npu.driver = "amdxdna";
        npu.maxTOPS = 10.0; // Typical AMD NPU performance
        npu.powerConsumption = 3.0;
        npu.supportedFormats = {"ONNX", "TensorFlow"};

        qDebug() << "AMD NPU detected";
    }

    return npu;
}

NPUInfo HardwareDetector::detectNVIDIANPU() {
    NPUInfo npu;

    // NVIDIA typically uses GPU for AI acceleration
    // Check for dedicated AI hardware
    QString nvidiaOutput = executeCommand("nvidia-smi -L | grep -i 'ai\\|inference'");
    if (!nvidiaOutput.isEmpty()) {
        npu.available = true;
        npu.name = "NVIDIA AI Accelerator";
        npu.deviceId = "nvidia";
        npu.driver = "nvidia";
        npu.maxTOPS = 20.0; // Typical NVIDIA AI accelerator
        npu.powerConsumption = 5.0;
        npu.supportedFormats = {"ONNX", "TensorRT", "TensorFlow"};

        qDebug() << "NVIDIA NPU/AI Accelerator detected";
    }

    return npu;
}

TPMInfo HardwareDetector::detectTPMInternal() {
    TPMInfo tpm;

#ifdef Q_OS_LINUX
    return detectLinuxTPM();
#elif defined(Q_OS_WIN)
    return detectWindowsTPM();
#elif defined(Q_OS_MAC)
    return detectMacTPM();
#else
    return tpm;
#endif
}

TPMInfo HardwareDetector::detectLinuxTPM() {
    TPMInfo tpm;

    // Check for TPM device files
    QStringList tpmDevices = {"/dev/tpm0", "/dev/tpmrm0"};

    for (const QString &device : tpmDevices) {
        if (QFile::exists(device)) {
            tpm.available = true;
            tpm.devicePath = device;
            break;
        }
    }

    if (tpm.available) {
        // Get TPM version from sysfs
        QFile versionFile("/sys/class/tpm/tpm0/tpm_version_major");
        if (versionFile.open(QIODevice::ReadOnly)) {
            QString versionMajor = versionFile.readAll().trimmed();
            if (versionMajor == "2") {
                tpm.version = "2.0";
            } else if (versionMajor == "1") {
                tpm.version = "1.2";
            }
        }

        // Get manufacturer information
        QFile mfgFile("/sys/class/tpm/tpm0/device/caps");
        if (mfgFile.open(QIODevice::ReadOnly)) {
            QString caps = mfgFile.readAll();
            if (caps.contains("STM")) {
                tpm.manufacturer = "STMicroelectronics";
            } else if (caps.contains("INTC")) {
                tpm.manufacturer = "Intel";
            } else if (caps.contains("AMD")) {
                tpm.manufacturer = "AMD";
            }
        }

        // Check for FIPS compliance
        QFile fipsFile("/sys/class/tpm/tpm0/fips");
        if (fipsFile.open(QIODevice::ReadOnly)) {
            QString fips = fipsFile.readAll().trimmed();
            tpm.fipsCompliant = (fips == "1");
        }

        // Get supported algorithms
        tpm.algorithms = {"SHA-384", "SHA-512", "ECC"};
        if (tpm.version == "2.0") {
            tpm.algorithms.append({"AES", "HMAC", "ECDSA", "ECDH"});
            tpm.attestationSupport = true;
            tpm.keySlots = 24; // Typical TPM 2.0 key slots
        } else {
            tpm.keySlots = 16; // Typical TPM 1.2 key slots
        }

        qDebug() << "TPM detected:" << tpm.version << "by" << tpm.manufacturer << "at" << tpm.devicePath;
    }

    return tpm;
}

TPMInfo HardwareDetector::detectWindowsTPM() {
    TPMInfo tpm;
    // Windows TPM detection would use WMI queries
    // Placeholder for Windows implementation
    return tpm;
}

TPMInfo HardwareDetector::detectMacTPM() {
    TPMInfo tpm;
    // macOS uses Secure Enclave instead of traditional TPM
    // Check for Secure Enclave availability
    QString systemInfo = executeCommand("system_profiler SPHardwareDataType");
    if (systemInfo.contains("Secure Enclave")) {
        tpm.available = true;
        tpm.version = "Secure Enclave";
        tpm.manufacturer = "Apple";
        tpm.devicePath = "secure_enclave";
        tpm.algorithms = {"AES", "ECC", "ECDSA"};
        tpm.attestationSupport = true;
        tpm.fipsCompliant = true;
        tpm.keySlots = 32; // Secure Enclave capacity
    }
    return tpm;
}

OpenVINOInfo HardwareDetector::detectOpenVINOInternal() {
    OpenVINOInfo openvino;

    // Check for OpenVINO installation
    if (!detectOpenVINOInstallation()) {
        return openvino;
    }

    openvino.available = true;

    // Get version
    openvino.version = getOpenVINOVersion();

    // Detect available devices
    openvino.availableDevices = detectOpenVINODevices();

    // Check for common installation paths
    QStringList installPaths = {
        "/opt/intel/openvino",
        "/opt/openvino",
        QString("%1/intel/openvino").arg(QDir::homePath()),
        "C:\\Program Files (x86)\\Intel\\openvino",
        "C:\\intel\\openvino"
    };

    for (const QString &path : installPaths) {
        if (QDir(path).exists()) {
            openvino.installPath = path;
            break;
        }
    }

    // Check runtime capabilities
    openvino.supportedFormats = {"ONNX", "OpenVINO IR", "PaddlePaddle", "TensorFlow", "TensorFlow Lite"};
    openvino.optimizationsEnabled = QFile::exists(openvino.installPath + "/deployment_tools/model_optimizer");

    // Get runtime version
    QString runtimeCheck = executeCommand("python3 -c \"import openvino; print(openvino.__version__)\"");
    if (!runtimeCheck.isEmpty()) {
        openvino.runtimeVersion = runtimeCheck.trimmed();
    }

    qDebug() << "OpenVINO detected:" << openvino.version << "at" << openvino.installPath;
    qDebug() << "Available devices:" << openvino.availableDevices.join(", ");

    return openvino;
}

bool HardwareDetector::detectOpenVINOInstallation() {
    // Check if OpenVINO is installed via Python
    QString pythonCheck = executeCommand("python3 -c \"import openvino; print('OK')\"");
    if (pythonCheck.contains("OK")) {
        return true;
    }

    // Check for standalone installation
    QStringList checkPaths = {"/opt/intel/openvino", "/opt/openvino"};
    for (const QString &path : checkPaths) {
        if (QDir(path).exists()) {
            return true;
        }
    }

    return false;
}

QStringList HardwareDetector::detectOpenVINODevices() {
    QStringList devices;

    // Use Python script to detect devices
    QString script = "import openvino as ov; "
                    "core = ov.Core(); "
                    "devices = core.available_devices; "
                    "print(','.join(devices))";

    QString deviceOutput = executeCommand(QString("python3 -c \"%1\"").arg(script));
    if (!deviceOutput.isEmpty()) {
        devices = deviceOutput.trimmed().split(',');
    }

    // Fallback: check for common devices
    if (devices.isEmpty()) {
        devices.append("CPU"); // Always available

        // Check for GPU
        if (QFile::exists("/dev/dri/card0") || !executeCommand("lspci | grep VGA").isEmpty()) {
            devices.append("GPU");
        }

        // Check for NPU
        if (QFile::exists("/dev/accel/accel0")) {
            devices.append("NPU");
        }
    }

    return devices;
}

QString HardwareDetector::getOpenVINOVersion() {
    QString version = executeCommand("python3 -c \"import openvino; print(openvino.__version__)\"");
    if (!version.isEmpty()) {
        return version.trimmed();
    }

    // Check version file
    QStringList versionFiles = {
        "/opt/intel/openvino/version.txt",
        "/opt/openvino/version.txt"
    };

    for (const QString &file : versionFiles) {
        QFile versionFile(file);
        if (versionFile.open(QIODevice::ReadOnly)) {
            return versionFile.readAll().trimmed();
        }
    }

    return "Unknown";
}

CPUInfo HardwareDetector::detectCPUInternal() {
    CPUInfo cpu;

#ifdef Q_OS_LINUX
    // Read CPU information from /proc/cpuinfo
    QFile cpuinfoFile("/proc/cpuinfo");
    if (cpuinfoFile.open(QIODevice::ReadOnly)) {
        QString cpuinfo = cpuinfoFile.readAll();

        // Extract CPU name
        QRegularExpression nameRegex("model name\\s*:\\s*(.+)");
        auto match = nameRegex.match(cpuinfo);
        if (match.hasMatch()) {
            cpu.name = match.captured(1).trimmed();
        }

        // Count cores and threads
        cpu.cores = cpuinfo.count("core id");
        cpu.threads = cpuinfo.count("processor");
        if (cpu.cores == 0) cpu.cores = cpu.threads;

        // Extract features
        QRegularExpression flagsRegex("flags\\s*:\\s*(.+)");
        match = flagsRegex.match(cpuinfo);
        if (match.hasMatch()) {
            cpu.features = match.captured(1).split(' ', Qt::SkipEmptyParts);

            cpu.aesniSupport = cpu.features.contains("aes");
            cpu.avxSupport = cpu.features.contains("avx");
            cpu.avx512Support = cpu.features.contains("avx512f");
        }

        // Get vendor
        QRegularExpression vendorRegex("vendor_id\\s*:\\s*(.+)");
        match = vendorRegex.match(cpuinfo);
        if (match.hasMatch()) {
            QString vendorId = match.captured(1).trimmed();
            if (vendorId == "GenuineIntel") {
                cpu.vendor = "Intel";
            } else if (vendorId == "AuthenticAMD") {
                cpu.vendor = "AMD";
            } else {
                cpu.vendor = vendorId;
            }
        }
    }
#endif

    // Get architecture
    cpu.architecture = QSysInfo::currentCpuArchitecture();

    // Get frequency from scaling governor
    QFile freqFile("/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq");
    if (freqFile.open(QIODevice::ReadOnly)) {
        QString freqStr = freqFile.readAll().trimmed();
        bool ok;
        double freqKHz = freqStr.toDouble(&ok);
        if (ok) {
            cpu.frequency = freqKHz / 1000000.0; // Convert KHz to GHz
        }
    }

    // Get cache size
    QFile cacheFile("/sys/devices/system/cpu/cpu0/cache/index2/size");
    if (cacheFile.open(QIODevice::ReadOnly)) {
        QString cacheStr = cacheFile.readAll().trimmed();
        if (cacheStr.endsWith('K')) {
            cpu.cacheSize = cacheStr.left(cacheStr.length() - 1).toInt();
        }
    }

    qDebug() << "CPU detected:" << cpu.name << cpu.cores << "cores," << cpu.threads << "threads";
    qDebug() << "CPU features:" << (cpu.aesniSupport ? "AES-NI" : "")
             << (cpu.avxSupport ? "AVX" : "")
             << (cpu.avx512Support ? "AVX-512" : "");

    return cpu;
}

GPUInfo HardwareDetector::detectGPUInternal() {
    GPUInfo gpu;

    // Try Intel GPU first
    auto intelGPU = detectIntelGPU();
    if (intelGPU.available) {
        return intelGPU;
    }

    // Try AMD GPU
    auto amdGPU = detectAMDGPU();
    if (amdGPU.available) {
        return amdGPU;
    }

    // Try NVIDIA GPU
    auto nvidiaGPU = detectNVIDIAGPU();
    if (nvidiaGPU.available) {
        return nvidiaGPU;
    }

    return gpu;
}

GPUInfo HardwareDetector::detectIntelGPU() {
    GPUInfo gpu;

    QString lspciOutput = executeCommand("lspci -nn | grep -i 'intel.*graphics\\|intel.*display'");
    if (!lspciOutput.isEmpty()) {
        gpu.available = true;
        gpu.name = "Intel Graphics";
        gpu.vendor = "Intel";
        gpu.driver = "i915";

        // Extract device ID
        QRegularExpression deviceRegex("\\[([0-9a-fA-F]{4}):([0-9a-fA-F]{4})\\]");
        auto match = deviceRegex.match(lspciOutput);
        if (match.hasMatch()) {
            gpu.deviceId = match.captured(2);
        }

        // Check for OpenCL support
        QString openclCheck = executeCommand("clinfo | grep -i intel");
        gpu.openclSupport = !openclCheck.isEmpty();

        // Check for Vulkan support
        QString vulkanCheck = executeCommand("vulkaninfo | grep -i intel");
        gpu.vulkanSupport = !vulkanCheck.isEmpty();

        // Estimate compute units based on known Intel GPU architectures
        if (gpu.deviceId.startsWith("7d")) { // Meteor Lake
            gpu.computeUnits = 128;
            gpu.memory = 2048; // Shared memory
        }

        qDebug() << "Intel GPU detected:" << gpu.name << "Device ID:" << gpu.deviceId;
    }

    return gpu;
}

GPUInfo HardwareDetector::detectAMDGPU() {
    GPUInfo gpu;

    QString lspciOutput = executeCommand("lspci -nn | grep -i 'amd.*radeon\\|amd.*graphics'");
    if (!lspciOutput.isEmpty()) {
        gpu.available = true;
        gpu.name = "AMD Radeon";
        gpu.vendor = "AMD";
        gpu.driver = "amdgpu";

        // Extract more detailed information
        QString rocmCheck = executeCommand("rocm-smi -i 0 --showproductname");
        if (!rocmCheck.isEmpty()) {
            gpu.name = rocmCheck.trimmed();
        }

        gpu.openclSupport = !executeCommand("clinfo | grep -i amd").isEmpty();
        gpu.vulkanSupport = !executeCommand("vulkaninfo | grep -i amd").isEmpty();

        qDebug() << "AMD GPU detected:" << gpu.name;
    }

    return gpu;
}

GPUInfo HardwareDetector::detectNVIDIAGPU() {
    GPUInfo gpu;

    QString nvidiaOutput = executeCommand("nvidia-smi -L");
    if (!nvidiaOutput.isEmpty()) {
        gpu.available = true;
        gpu.vendor = "NVIDIA";
        gpu.driver = "nvidia";

        // Extract GPU name
        QRegularExpression nameRegex("GPU \\d+: (.+) \\(");
        auto match = nameRegex.match(nvidiaOutput);
        if (match.hasMatch()) {
            gpu.name = match.captured(1);
        }

        // Get memory information
        QString memoryOutput = executeCommand("nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits");
        bool ok;
        int memory = memoryOutput.trimmed().toInt(&ok);
        if (ok) {
            gpu.memory = memory; // MB
        }

        gpu.openclSupport = true; // NVIDIA GPUs generally support OpenCL
        gpu.vulkanSupport = true; // Modern NVIDIA GPUs support Vulkan

        qDebug() << "NVIDIA GPU detected:" << gpu.name << "Memory:" << gpu.memory << "MB";
    }

    return gpu;
}

double HardwareDetector::calculateOverallScore() const {
    double score = 0.0;

    // NPU contributes 30% to overall score
    score += calculateNPUScore(_profile.npu) * 0.3;

    // TPM contributes 25% to overall score
    score += calculateTPMScore(_profile.tpm) * 0.25;

    // CPU contributes 25% to overall score
    score += calculateCPUScore(_profile.cpu) * 0.25;

    // GPU contributes 20% to overall score
    score += calculateGPUScore(_profile.gpu) * 0.2;

    return qBound(0.0, score, 100.0);
}

double HardwareDetector::calculateNPUScore(const NPUInfo &npu) const {
    if (!npu.available) {
        return 0.0;
    }

    double score = 40.0; // Base score for having NPU

    // Add points for performance
    if (npu.maxTOPS > 0) {
        score += qMin(30.0, npu.maxTOPS * 2.0); // Up to 30 points for performance
    }

    // Add points for OpenVINO support
    if (npu.openvinoSupport) {
        score += 20.0;
    }

    // Add points for driver availability
    if (!npu.driver.isEmpty()) {
        score += 10.0;
    }

    return qBound(0.0, score, 100.0);
}

double HardwareDetector::calculateTPMScore(const TPMInfo &tpm) const {
    if (!tpm.available) {
        return 0.0;
    }

    double score = 50.0; // Base score for having TPM

    // TPM 2.0 gets higher score
    if (tpm.version == "2.0") {
        score += 30.0;
    } else if (tpm.version == "1.2") {
        score += 15.0;
    }

    // FIPS compliance adds points
    if (tpm.fipsCompliant) {
        score += 10.0;
    }

    // Attestation support adds points
    if (tpm.attestationSupport) {
        score += 10.0;
    }

    return qBound(0.0, score, 100.0);
}

double HardwareDetector::calculateCPUScore(const CPUInfo &cpu) const {
    double score = 20.0; // Base score

    // Add points for cores
    score += qMin(20.0, cpu.cores * 2.0);

    // Add points for cryptographic features
    if (cpu.aesniSupport) score += 15.0;
    if (cpu.avxSupport) score += 10.0;
    if (cpu.avx512Support) score += 15.0;

    // Add points for frequency
    if (cpu.frequency > 0) {
        score += qMin(20.0, cpu.frequency * 5.0);
    }

    return qBound(0.0, score, 100.0);
}

double HardwareDetector::calculateGPUScore(const GPUInfo &gpu) const {
    if (!gpu.available) {
        return 0.0;
    }

    double score = 30.0; // Base score for having GPU

    // Add points for compute support
    if (gpu.openclSupport) score += 20.0;
    if (gpu.vulkanSupport) score += 15.0;

    // Add points for memory
    if (gpu.memory > 0) {
        score += qMin(25.0, gpu.memory / 100.0); // 1 point per 100MB, up to 25 points
    }

    // Add points for compute units
    if (gpu.computeUnits > 0) {
        score += qMin(10.0, gpu.computeUnits / 10.0);
    }

    return qBound(0.0, score, 100.0);
}

QString HardwareDetector::executeCommand(const QString &command) {
    QProcess process;
    process.start("/bin/sh", QStringList() << "-c" << command);
    process.waitForFinished(5000); // 5 second timeout

    if (process.exitCode() == 0) {
        return QString::fromUtf8(process.readAllStandardOutput());
    }

    return QString();
}

QString HardwareDetector::getSystemInfo() const {
    QStringList info;

    info << QString("OS: %1").arg(QSysInfo::prettyProductName());
    info << QString("Kernel: %1").arg(QSysInfo::kernelVersion());
    info << QString("Architecture: %1").arg(QSysInfo::currentCpuArchitecture());

#ifdef Q_OS_LINUX
    struct utsname unameData;
    if (uname(&unameData) == 0) {
        info << QString("Machine: %1").arg(unameData.machine);
    }
#endif

    return info.join("; ");
}

void HardwareDetector::onMonitoringTimer() {
    // Refresh hardware status periodically
    refreshHardwareStatus();
}

void HardwareDetector::refreshHardwareStatus() {
    // Quick status check without full detection
    bool npuAvailable = QFile::exists("/dev/accel/accel0");
    bool tpmAvailable = QFile::exists("/dev/tpm0");

    if (npuAvailable != _profile.npu.available) {
        Q_EMIT hardwareStatusChanged("NPU", npuAvailable);
    }

    if (tpmAvailable != _profile.tpm.available) {
        Q_EMIT hardwareStatusChanged("TPM", tpmAvailable);
    }
}

void HardwareDetector::startContinuousMonitoring(int intervalMs) {
    if (_continuousMonitoring) {
        return;
    }

    _monitoringTimer->start(intervalMs);
    _continuousMonitoring = true;

    qDebug() << "Started continuous hardware monitoring with interval:" << intervalMs << "ms";
}

void HardwareDetector::stopContinuousMonitoring() {
    if (!_continuousMonitoring) {
        return;
    }

    _monitoringTimer->stop();
    _continuousMonitoring = false;

    qDebug() << "Stopped continuous hardware monitoring";
}

// Utility functions implementation
namespace HardwareUtils {

QString hardwareDetectionResultToString(HardwareDetectionResult result) {
    switch (result) {
    case HardwareDetectionResult::Success: return "Success";
    case HardwareDetectionResult::NotAvailable: return "Not Available";
    case HardwareDetectionResult::PermissionDenied: return "Permission Denied";
    case HardwareDetectionResult::DriverMissing: return "Driver Missing";
    case HardwareDetectionResult::VersionMismatch: return "Version Mismatch";
    case HardwareDetectionResult::TestFailed: return "Test Failed";
    case HardwareDetectionResult::UnknownError: return "Unknown Error";
    }
    return "Unknown";
}

bool isHardwareSecurityCapable(const HardwareProfile &profile) {
    return profile.tpm.available && (profile.tpm.version == "2.0" || profile.tpm.version == "Secure Enclave");
}

bool isAIAccelerationCapable(const HardwareProfile &profile) {
    return profile.npu.available || profile.gpu.available || profile.openvino.available;
}

QString formatHardwareProfile(const HardwareProfile &profile) {
    QStringList parts;

    if (profile.npu.available) {
        parts << QString("NPU: %1").arg(profile.npu.name);
    }

    if (profile.tpm.available) {
        parts << QString("TPM: %1").arg(profile.tpm.version);
    }

    if (profile.openvino.available) {
        parts << QString("OpenVINO: %1").arg(profile.openvino.version);
    }

    parts << QString("CPU: %1 (%2 cores)").arg(profile.cpu.name).arg(profile.cpu.cores);

    if (profile.gpu.available) {
        parts << QString("GPU: %1").arg(profile.gpu.name);
    }

    parts << QString("Score: %1").arg(profile.overallScore, 0, 'f', 1);

    return parts.join(", ");
}

} // namespace HardwareUtils

// Additional method implementations
HardwareProfile HardwareDetector::getHardwareProfile() const {
    QMutexLocker locker(&_mutex);
    return _profile;
}

NPUInfo HardwareDetector::getNPUInfo() const {
    QMutexLocker locker(&_mutex);
    return _profile.npu;
}

TPMInfo HardwareDetector::getTPMInfo() const {
    QMutexLocker locker(&_mutex);
    return _profile.tpm;
}

OpenVINOInfo HardwareDetector::getOpenVINOInfo() const {
    QMutexLocker locker(&_mutex);
    return _profile.openvino;
}

CPUInfo HardwareDetector::getCPUInfo() const {
    QMutexLocker locker(&_mutex);
    return _profile.cpu;
}

GPUInfo HardwareDetector::getGPUInfo() const {
    QMutexLocker locker(&_mutex);
    return _profile.gpu;
}

bool HardwareDetector::isNPUAvailable() const {
    QMutexLocker locker(&_mutex);
    return _profile.npu.available;
}

bool HardwareDetector::isTPMAvailable() const {
    QMutexLocker locker(&_mutex);
    return _profile.tpm.available;
}

bool HardwareDetector::isOpenVINOAvailable() const {
    QMutexLocker locker(&_mutex);
    return _profile.openvino.available;
}

bool HardwareDetector::hasHardwareAcceleration() const {
    QMutexLocker locker(&_mutex);
    return _profile.npu.available || _profile.gpu.available;
}

bool HardwareDetector::hasSecureHardware() const {
    QMutexLocker locker(&_mutex);
    return _profile.tpm.available;
}

bool HardwareDetector::testOpenVINODevice(const QString &device) {
    // Simple OpenVINO device test
    QString script = QString("import openvino as ov; "
                            "core = ov.Core(); "
                            "try: "
                                "devices = core.available_devices; "
                                "print('true' if '%1' in devices else 'false');"
                            "except: "
                                "print('false')").arg(device);

    QString result = executeCommand(QString("python3 -c \"%1\"").arg(script));
    return result.trimmed() == "true";
}

void HardwareDetector::detectNPU() {
    QMutexLocker locker(&_mutex);
    _profile.npu = detectNPUInternal();
    Q_EMIT npuDetected(_profile.npu);
}

void HardwareDetector::detectTPM() {
    QMutexLocker locker(&_mutex);
    _profile.tpm = detectTPMInternal();
    Q_EMIT tpmDetected(_profile.tpm);
}

void HardwareDetector::detectOpenVINO() {
    QMutexLocker locker(&_mutex);
    _profile.openvino = detectOpenVINOInternal();
    Q_EMIT openvinoDetected(_profile.openvino);
}

void HardwareDetector::detectCPU() {
    QMutexLocker locker(&_mutex);
    _profile.cpu = detectCPUInternal();
}

void HardwareDetector::detectGPU() {
    QMutexLocker locker(&_mutex);
    _profile.gpu = detectGPUInternal();
}

bool HardwareDetector::isContinuousMonitoringActive() const {
    return _continuousMonitoring;
}

base::expected<QStringList, HardwareDetectionResult> HardwareDetector::getNPUDeviceList() {
    if (isCacheValid() && !_cachedNPUDevices.isEmpty()) {
        return _cachedNPUDevices;
    }

    QStringList devices;

    // Check for Intel NPU devices
    QStringList npuPaths = {"/dev/accel/accel0", "/dev/intel_vpu"};
    for (const QString &path : npuPaths) {
        if (QFile::exists(path)) {
            devices.append(path);
        }
    }

    // Check via lspci
    QString lspciOutput = executeCommand("lspci | grep -i 'neural\\|npu\\|ai'");
    if (!lspciOutput.isEmpty() && devices.isEmpty()) {
        devices.append("pci_npu");
    }

    if (devices.isEmpty()) {
        return base::make_unexpected(HardwareDetectionResult::NotAvailable);
    }

    _cachedNPUDevices = devices;
    _cacheTime = QDateTime::currentDateTime();

    return devices;
}

base::expected<QString, HardwareDetectionResult> HardwareDetector::getTPMDevicePath() {
    if (isCacheValid() && !_cachedTPMPath.isEmpty()) {
        return _cachedTPMPath;
    }

    QStringList tpmPaths = {"/dev/tpm0", "/dev/tpmrm0"};

    for (const QString &path : tpmPaths) {
        if (QFile::exists(path)) {
            _cachedTPMPath = path;
            _cacheTime = QDateTime::currentDateTime();
            return path;
        }
    }

    return base::make_unexpected(HardwareDetectionResult::NotAvailable);
}

base::expected<QStringList, HardwareDetectionResult> HardwareDetector::getOpenVINODevices() {
    if (isCacheValid() && !_cachedOpenVINODevices.isEmpty()) {
        return _cachedOpenVINODevices;
    }

    QStringList devices = detectOpenVINODevices();

    if (devices.isEmpty()) {
        return base::make_unexpected(HardwareDetectionResult::NotAvailable);
    }

    _cachedOpenVINODevices = devices;
    _cacheTime = QDateTime::currentDateTime();

    return devices;
}

bool HardwareDetector::isCacheValid() const {
    return _cacheTime.msecsTo(QDateTime::currentDateTime()) < CacheValidityMs;
}

void HardwareDetector::clearCache() {
    _cachedNPUDevices.clear();
    _cachedTPMPath.clear();
    _cachedOpenVINODevices.clear();
    _cacheTime = QDateTime::currentDateTime().addSecs(-CacheValidityMs / 1000);
}

BenchmarkResults HardwareDetector::getBenchmarkResults() const {
    QMutexLocker locker(&_mutex);
    return _benchmarkResults;
}

void HardwareDetector::runBenchmarks() {
    qDebug() << "Starting hardware benchmarks...";

    BenchmarkResults results;
    results.benchmarkTime = QDateTime::currentDateTime();

    // Run crypto benchmark
    results.crypto = runCryptoBenchmark();

    // Run AI benchmark if possible
    if (isNPUAvailable() || isOpenVINOAvailable()) {
        results.ai = runAIBenchmark();
    }

    // Measure memory bandwidth
    results.memoryBandwidth = measureMemoryBandwidth();

    // Measure disk I/O latency
    results.diskIOLatency = measureDiskIOLatency();

    // Determine which hardware was used
    QStringList hardwareUsed;
    if (_profile.npu.available) hardwareUsed << "NPU";
    if (_profile.gpu.available) hardwareUsed << "GPU";
    hardwareUsed << "CPU";
    results.hardwareUsed = hardwareUsed.join(", ");

    {
        QMutexLocker locker(&_mutex);
        _benchmarkResults = results;
        _benchmarkComplete = true;
    }

    qDebug() << "Benchmarks completed";
    Q_EMIT benchmarkComplete(results);
}

BenchmarkResults::CryptoTest HardwareDetector::runCryptoBenchmark() {
    BenchmarkResults::CryptoTest crypto;

    // Simple timing test for AES256 (placeholder)
    auto start = QDateTime::currentMSecsSinceEpoch();

    // Simulate crypto operations
    QThread::msleep(10); // Placeholder timing

    auto end = QDateTime::currentMSecsSinceEpoch();
    double duration = (end - start) / 1000.0;

    // Estimate throughput (placeholder values)
    crypto.aes256Throughput = 100.0; // MB/s
    crypto.sha256Throughput = 150.0; // MB/s
    crypto.ed25519SignLatency = 0.5; // ms
    crypto.x25519DhLatency = 0.3; // ms

    return crypto;
}

BenchmarkResults::AITest HardwareDetector::runAIBenchmark() {
    BenchmarkResults::AITest ai;

    if (!isOpenVINOAvailable()) {
        return ai;
    }

    // Simple AI inference test (placeholder)
    auto start = QDateTime::currentMSecsSinceEpoch();

    // Simulate AI inference
    QThread::msleep(50); // Placeholder timing

    auto end = QDateTime::currentMSecsSinceEpoch();

    ai.inferenceLatency = end - start; // ms
    ai.throughput = 1000.0 / ai.inferenceLatency; // inferences/sec
    ai.accuracy = 0.95; // 95% placeholder
    ai.modelUsed = "test_model";

    return ai;
}

double HardwareDetector::measureMemoryBandwidth() {
    // Placeholder memory bandwidth measurement
    return 25600.0; // MB/s (typical DDR4-3200)
}

double HardwareDetector::measureDiskIOLatency() {
    // Simple disk I/O test
    QString tempFile = QStandardPaths::writableLocation(QStandardPaths::TempLocation) + "/hardware_test.tmp";

    auto start = QDateTime::currentMSecsSinceEpoch();

    QFile file(tempFile);
    if (file.open(QIODevice::WriteOnly)) {
        file.write(QByteArray(1024, 'x')); // Write 1KB
        file.flush();
        file.close();

        // Read it back
        if (file.open(QIODevice::ReadOnly)) {
            file.readAll();
            file.close();
        }

        // Clean up
        file.remove();
    }

    auto end = QDateTime::currentMSecsSinceEpoch();

    return end - start; // ms
}

QString HardwareDetector::getDistribution() const {
    QString distro = executeCommand("lsb_release -d -s");
    if (distro.isEmpty()) {
        QFile osRelease("/etc/os-release");
        if (osRelease.open(QIODevice::ReadOnly)) {
            QString content = osRelease.readAll();
            QRegularExpression nameRegex("PRETTY_NAME=\"([^\"]+)\"");
            auto match = nameRegex.match(content);
            if (match.hasMatch()) {
                distro = match.captured(1);
            }
        }
    }
    return distro.isEmpty() ? "Unknown" : distro;
}

QString HardwareDetector::getKernelVersion() const {
    return QSysInfo::kernelVersion();
}

QStringList HardwareDetector::getLoadedDrivers() const {
    QString lsmodOutput = executeCommand("lsmod");
    QStringList drivers;

    if (!lsmodOutput.isEmpty()) {
        QStringList lines = lsmodOutput.split('\n', Qt::SkipEmptyParts);
        for (int i = 1; i < lines.size(); ++i) { // Skip header
            QString line = lines[i];
            QStringList parts = line.split(' ', Qt::SkipEmptyParts);
            if (!parts.isEmpty()) {
                drivers.append(parts[0]);
            }
        }
    }

    return drivers;
}

void HardwareDetector::onDetectionFinished() {
    // Called when detection completes
    qDebug() << "Hardware detection finished";
}

void HardwareDetector::onBenchmarkFinished() {
    // Called when benchmarks complete
    qDebug() << "Hardware benchmarks finished";
}

} // namespace Security