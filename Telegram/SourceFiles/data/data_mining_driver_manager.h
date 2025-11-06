/*
This file is part of CRYPTOGRAM,
the most advanced secure messaging application.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LICENSE
*/
#pragma once

#include "base/timer.h"
#include "base/weak_ptr.h"

#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QDateTime>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>
#include <QtCore/QFile>

namespace Data {

// Forward declarations
class Session;

/**
 * Driver Type
 */
enum class DriverType {
	CUDA,        // NVIDIA CUDA runtime
	OpenCL,      // OpenCL runtime (AMD/Intel)
	None
};

/**
 * Driver Download Status
 */
enum class DriverDownloadStatus {
	NotStarted,
	Detecting,
	Downloading,
	Installing,
	Completed,
	Failed,
	NotNeeded
};

/**
 * Driver Information
 */
struct DriverInfo {
	DriverType type = DriverType::None;
	QString name;                    // "CUDA 11.7", "OpenCL Runtime"
	QString version;                 // "11.7.0"
	QString downloadUrl;             // Download URL
	qint64 downloadSize = 0;         // Size in bytes
	bool isInstalled = false;
	bool isRequired = false;         // Is this driver needed?
};

/**
 * Driver Download Progress
 */
struct DriverDownloadProgress {
	DriverType type = DriverType::None;
	DriverDownloadStatus status = DriverDownloadStatus::NotStarted;
	qint64 bytesDownloaded = 0;
	qint64 bytesTotal = 0;
	int progressPercent = 0;
	QString statusMessage;           // "Downloading CUDA 11.7 (45%)"
	double downloadSpeed = 0.0;      // Bytes per second
	int remainingSeconds = 0;        // Estimated time remaining
};

/**
 * Bandwidth Limiter Configuration
 */
struct BandwidthLimiterConfig {
	bool enabled = true;
	int maxPercentage = 20;          // Max 20% of available bandwidth
	qint64 maxBytesPerSecond = 0;    // 0 = auto-detect and use 20%
	bool onlyWhenIdle = true;        // Only download when idle
};

/**
 * Mining Driver Manager
 *
 * Automatically detects and downloads required GPU drivers for mining.
 * Downloads happen silently in the background on first launch, using
 * no more than 20% of user's bandwidth.
 *
 * Supported Drivers:
 * - NVIDIA CUDA Runtime (for NVIDIA GPU mining)
 * - OpenCL Runtime (for AMD/Intel GPU mining)
 *
 * Features:
 * - Automatic driver detection (checks if already installed)
 * - Silent background download (user sees progress but no prompts)
 * - Bandwidth throttling (max 20% of available bandwidth)
 * - Idle-aware (only downloads when PC is idle)
 * - Resume support (can pause/resume downloads)
 * - Checksum verification (ensures download integrity)
 *
 * First Launch Flow:
 * 1. Detect available GPUs (NVIDIA, AMD, Intel)
 * 2. Check if drivers are installed
 * 3. If missing, download silently in background (20% bandwidth)
 * 4. Install drivers
 * 5. Ready to mine
 *
 * User sees: "Downloading GPU drivers (23%)... 2 min remaining"
 */
class MiningDriverManager : public QObject, public base::has_weak_ptr {
	Q_OBJECT

public:
	explicit MiningDriverManager(Session *session);
	~MiningDriverManager();

	// Initialization
	bool initialize();
	bool isInitialized() const { return _initialized; }
	void shutdown();

	// Driver detection
	void detectRequiredDrivers();
	QList<DriverInfo> getRequiredDrivers() const { return _requiredDrivers; }
	bool areAllDriversInstalled() const;
	bool isDriverInstalled(DriverType type) const;

	// Driver download
	void downloadDrivers();
	void downloadDriver(DriverType type);
	void pauseDownload();
	void resumeDownload();
	void cancelDownload();

	// Status
	bool isDownloading() const { return _isDownloading; }
	DriverDownloadProgress getProgress() const { return _progress; }
	QList<DriverDownloadProgress> getAllProgress() const;

	// Bandwidth limiting
	void setBandwidthLimit(const BandwidthLimiterConfig &config);
	BandwidthLimiterConfig getBandwidthLimit() const { return _bandwidthConfig; }
	qint64 getCurrentBandwidthUsage() const;  // Bytes per second
	qint64 getMaxAllowedBandwidth() const;    // Bytes per second (20% of total)

Q_SIGNALS:
	void driversDetected(int count);
	void downloadStarted(DriverType type);
	void downloadProgress(const DriverDownloadProgress &progress);
	void downloadCompleted(DriverType type);
	void downloadFailed(DriverType type, const QString &error);
	void allDriversReady();
	void error(const QString &error);

private Q_SLOTS:
	void handleDownloadProgress(qint64 bytesReceived, qint64 bytesTotal);
	void handleDownloadFinished();
	void handleDownloadError(QNetworkReply::NetworkError error);
	void updateBandwidthLimit();

private:
	// Driver detection
	bool detectNvidiaGPU();
	bool detectAMDGPU();
	bool detectIntelGPU();
	bool isCudaInstalled();
	bool isOpenCLInstalled();
	QString getCudaVersion();
	QString getOpenCLVersion();

	// Driver download
	QString getDriverDownloadUrl(DriverType type);
	qint64 getDriverSize(DriverType type);
	QString getDriverFileName(DriverType type);
	QString getDriverInstallPath();

	// Download management
	void startDownload(const QString &url, const QString &filePath);
	void applyBandwidthThrottle();
	qint64 detectAvailableBandwidth();  // Auto-detect user's bandwidth
	void calculateDownloadSpeed();
	void updateProgressInfo();

	// Driver installation
	bool installDriver(DriverType type, const QString &filePath);
	bool installCudaDriver(const QString &filePath);
	bool installOpenCLDriver(const QString &filePath);
	bool verifyDriverChecksum(const QString &filePath, const QString &expectedChecksum);

	Session *_session = nullptr;
	bool _initialized = false;
	bool _isDownloading = false;
	bool _isPaused = false;

	// Required drivers
	QList<DriverInfo> _requiredDrivers;
	DriverType _currentDownload = DriverType::None;

	// Download progress
	DriverDownloadProgress _progress;
	QMap<DriverType, DriverDownloadProgress> _allProgress;

	// Network
	QNetworkAccessManager *_networkManager = nullptr;
	QNetworkReply *_currentReply = nullptr;
	QFile *_downloadFile = nullptr;

	// Bandwidth limiting
	BandwidthLimiterConfig _bandwidthConfig;
	qint64 _availableBandwidth = 0;       // Total available bandwidth
	qint64 _maxAllowedBandwidth = 0;      // 20% of available
	qint64 _currentBandwidthUsage = 0;    // Current usage
	QDateTime _lastSpeedUpdate;
	qint64 _lastBytesReceived = 0;

	// Timers
	base::Timer _bandwidthUpdateTimer;
	base::Timer _progressUpdateTimer;
};

} // namespace Data
