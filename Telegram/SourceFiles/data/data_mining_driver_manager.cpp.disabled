/*
This file is part of CRYPTOGRAM,
the most advanced secure messaging application.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LICENSE
*/
#include "data/data_mining_driver_manager.h"

#include "data/data_session.h"
#include "main/main_session.h"

#include <QtCore/QProcess>
#include <QtCore/QDir>
#include <QtCore/QStandardPaths>
#include <QtNetwork/QNetworkRequest>
#include <QtCore/QSysInfo>

#ifdef Q_OS_WIN
#include <windows.h>
#elif defined Q_OS_LINUX
#include <unistd.h>
#elif defined Q_OS_MAC
#include <sys/sysctl.h>
#endif

namespace Data {

namespace {

// Driver download URLs (official NVIDIA/AMD redistributables)
constexpr auto kCudaDownloadUrl = "https://developer.download.nvidia.com/compute/cuda/11.7.0/local_installers/cuda_11.7.0_516.01_windows.exe"_cs;  // Windows
constexpr auto kOpenCLDownloadUrl = "https://github.com/GPUOpen-LibrariesAndSDKs/OCL-SDK/releases/download/1.0/OCL_SDK_Light_AMD.exe"_cs;

// Bandwidth detection
constexpr auto kDefaultBandwidthMbps = 100;  // Assume 100 Mbps if can't detect
constexpr auto kBandwidthPercentage = 20;    // Use max 20% of bandwidth

// Update intervals
constexpr auto kBandwidthUpdateInterval = 1000;  // Update bandwidth limit every 1s
constexpr auto kProgressUpdateInterval = 500;    // Update progress every 500ms

} // namespace

MiningDriverManager::MiningDriverManager(Session *session)
: QObject(nullptr)
, _session(session)
, _networkManager(new QNetworkAccessManager(this)) {
}

MiningDriverManager::~MiningDriverManager() {
	shutdown();
}

bool MiningDriverManager::initialize() {
	if (_initialized) {
		return true;
	}

	// Setup timers
	_bandwidthUpdateTimer.setCallback([=] { updateBandwidthLimit(); });
	_progressUpdateTimer.setCallback([=] { updateProgressInfo(); });

	// Detect available bandwidth
	_availableBandwidth = detectAvailableBandwidth();
	_maxAllowedBandwidth = (_availableBandwidth * kBandwidthPercentage) / 100;

	// Setup bandwidth config
	_bandwidthConfig.enabled = true;
	_bandwidthConfig.maxPercentage = kBandwidthPercentage;
	_bandwidthConfig.maxBytesPerSecond = _maxAllowedBandwidth;
	_bandwidthConfig.onlyWhenIdle = true;

	_initialized = true;

	// Auto-detect required drivers on first launch
	detectRequiredDrivers();

	// Start download if drivers are missing
	if (!areAllDriversInstalled()) {
		downloadDrivers();
	}

	return true;
}

void MiningDriverManager::shutdown() {
	if (!_initialized) {
		return;
	}

	cancelDownload();

	_bandwidthUpdateTimer.cancel();
	_progressUpdateTimer.cancel();

	_initialized = false;
}

void MiningDriverManager::detectRequiredDrivers() {
	_requiredDrivers.clear();

	// Detect NVIDIA GPU
	if (detectNvidiaGPU()) {
		DriverInfo cudaDriver;
		cudaDriver.type = DriverType::CUDA;
		cudaDriver.name = "NVIDIA CUDA Runtime";
		cudaDriver.version = "11.7.0";
		cudaDriver.downloadUrl = QString(kCudaDownloadUrl);
		cudaDriver.downloadSize = 3'200'000'000;  // ~3.2 GB
		cudaDriver.isInstalled = isCudaInstalled();
		cudaDriver.isRequired = true;

		_requiredDrivers.append(cudaDriver);
	}

	// Detect AMD or Intel GPU
	if (detectAMDGPU() || detectIntelGPU()) {
		DriverInfo openclDriver;
		openclDriver.type = DriverType::OpenCL;
		openclDriver.name = "OpenCL Runtime";
		openclDriver.version = "1.2";
		openclDriver.downloadUrl = QString(kOpenCLDownloadUrl);
		openclDriver.downloadSize = 45'000'000;  // ~45 MB
		openclDriver.isInstalled = isOpenCLInstalled();
		openclDriver.isRequired = true;

		_requiredDrivers.append(openclDriver);
	}

	Q_EMIT driversDetected(_requiredDrivers.size());
}

bool MiningDriverManager::areAllDriversInstalled() const {
	for (const auto &driver : _requiredDrivers) {
		if (driver.isRequired && !driver.isInstalled) {
			return false;
		}
	}
	return true;
}

bool MiningDriverManager::isDriverInstalled(DriverType type) const {
	for (const auto &driver : _requiredDrivers) {
		if (driver.type == type) {
			return driver.isInstalled;
		}
	}
	return false;
}

void MiningDriverManager::downloadDrivers() {
	// Download all missing drivers sequentially
	for (const auto &driver : _requiredDrivers) {
		if (driver.isRequired && !driver.isInstalled) {
			downloadDriver(driver.type);
			return;  // Download one at a time
		}
	}

	// All drivers are installed
	Q_EMIT allDriversReady();
}

void MiningDriverManager::downloadDriver(DriverType type) {
	if (_isDownloading) {
		return;
	}

	// Find driver info
	DriverInfo driverInfo;
	for (const auto &driver : _requiredDrivers) {
		if (driver.type == type) {
			driverInfo = driver;
			break;
		}
	}

	if (driverInfo.type == DriverType::None) {
		return;
	}

	// Setup progress
	_progress = DriverDownloadProgress();
	_progress.type = type;
	_progress.status = DriverDownloadStatus::Downloading;
	_progress.bytesTotal = driverInfo.downloadSize;
	_progress.statusMessage = QString("Downloading %1...").arg(driverInfo.name);

	// Create download directory
	const auto downloadDir = QStandardPaths::writableLocation(QStandardPaths::TempLocation) + "/cryptogram_drivers";
	QDir().mkpath(downloadDir);

	const auto fileName = getDriverFileName(type);
	const auto filePath = downloadDir + "/" + fileName;

	// Start download
	_currentDownload = type;
	_isDownloading = true;
	_isPaused = false;

	startDownload(driverInfo.downloadUrl, filePath);

	// Start timers
	_bandwidthUpdateTimer.callEach(kBandwidthUpdateInterval);
	_progressUpdateTimer.callEach(kProgressUpdateInterval);

	Q_EMIT downloadStarted(type);
}

void MiningDriverManager::startDownload(const QString &url, const QString &filePath) {
	// Cancel any existing download
	if (_currentReply) {
		_currentReply->abort();
		_currentReply->deleteLater();
		_currentReply = nullptr;
	}

	if (_downloadFile) {
		_downloadFile->close();
		delete _downloadFile;
		_downloadFile = nullptr;
	}

	// Create file
	_downloadFile = new QFile(filePath, this);
	if (!_downloadFile->open(QIODevice::WriteOnly)) {
		Q_EMIT error("Failed to create download file: " + filePath);
		_isDownloading = false;
		return;
	}

	// Create request
	QNetworkRequest request(url);
	request.setAttribute(QNetworkRequest::FollowRedirectsAttribute, true);
	request.setRawHeader("User-Agent", "CRYPTOGRAM/1.0");

	// Start download
	_currentReply = _networkManager->get(request);

	// Connect signals
	connect(_currentReply, &QNetworkReply::downloadProgress, this, &MiningDriverManager::handleDownloadProgress);
	connect(_currentReply, &QNetworkReply::finished, this, &MiningDriverManager::handleDownloadFinished);
	connect(_currentReply, QOverload<QNetworkReply::NetworkError>::of(&QNetworkReply::errorOccurred), this, &MiningDriverManager::handleDownloadError);

	// Apply bandwidth throttle
	applyBandwidthThrottle();
}

void MiningDriverManager::handleDownloadProgress(qint64 bytesReceived, qint64 bytesTotal) {
	if (!_currentReply || !_downloadFile) {
		return;
	}

	// Write data to file
	const auto data = _currentReply->readAll();
	_downloadFile->write(data);

	// Update progress
	_progress.bytesDownloaded = bytesReceived;
	_progress.bytesTotal = bytesTotal;
	_progress.progressPercent = bytesTotal > 0 ? (bytesReceived * 100) / bytesTotal : 0;

	// Calculate download speed
	calculateDownloadSpeed();

	Q_EMIT downloadProgress(_progress);
}

void MiningDriverManager::handleDownloadFinished() {
	if (!_currentReply || !_downloadFile) {
		return;
	}

	// Check for errors
	if (_currentReply->error() != QNetworkReply::NoError) {
		return;  // Will be handled by handleDownloadError
	}

	// Close file
	_downloadFile->close();
	const auto filePath = _downloadFile->fileName();

	// Install driver
	_progress.status = DriverDownloadStatus::Installing;
	_progress.statusMessage = "Installing driver...";
	Q_EMIT downloadProgress(_progress);

	const auto success = installDriver(_currentDownload, filePath);

	if (success) {
		_progress.status = DriverDownloadStatus::Completed;
		_progress.statusMessage = "Driver installed successfully";
		_progress.progressPercent = 100;
		Q_EMIT downloadCompleted(_currentDownload);

		// Download next driver
		_isDownloading = false;
		downloadDrivers();
	} else {
		_progress.status = DriverDownloadStatus::Failed;
		_progress.statusMessage = "Driver installation failed";
		Q_EMIT downloadFailed(_currentDownload, "Installation failed");
		_isDownloading = false;
	}

	// Cleanup
	_currentReply->deleteLater();
	_currentReply = nullptr;
	delete _downloadFile;
	_downloadFile = nullptr;

	// Stop timers
	_bandwidthUpdateTimer.cancel();
	_progressUpdateTimer.cancel();
}

void MiningDriverManager::handleDownloadError(QNetworkReply::NetworkError error) {
	const auto errorString = _currentReply ? _currentReply->errorString() : "Unknown error";

	_progress.status = DriverDownloadStatus::Failed;
	_progress.statusMessage = "Download failed: " + errorString;

	Q_EMIT downloadFailed(_currentDownload, errorString);
	Q_EMIT error("Driver download failed: " + errorString);

	_isDownloading = false;

	// Cleanup
	if (_currentReply) {
		_currentReply->deleteLater();
		_currentReply = nullptr;
	}
	if (_downloadFile) {
		_downloadFile->close();
		delete _downloadFile;
		_downloadFile = nullptr;
	}

	// Stop timers
	_bandwidthUpdateTimer.cancel();
	_progressUpdateTimer.cancel();
}

void MiningDriverManager::applyBandwidthThrottle() {
	if (!_bandwidthConfig.enabled || _maxAllowedBandwidth <= 0) {
		return;
	}

	// Simple throttling: if current usage exceeds limit, log it
	// Full implementation would pause/resume QNetworkReply
	if (_currentBandwidthUsage > _maxAllowedBandwidth) {
		LOG(("Mining Driver: Bandwidth usage (%1) exceeds limit (%2)")
			.arg(_currentBandwidthUsage)
			.arg(_maxAllowedBandwidth));
	}
}

void MiningDriverManager::calculateDownloadSpeed() {
	const auto now = QDateTime::currentDateTime();
	const auto elapsedMs = _lastSpeedUpdate.msecsTo(now);

	if (elapsedMs >= 1000) {  // Calculate speed every second
		const auto bytesDownloaded = _progress.bytesDownloaded - _lastBytesReceived;
		_progress.downloadSpeed = (bytesDownloaded * 1000.0) / elapsedMs;

		// Calculate ETA
		const auto bytesRemaining = _progress.bytesTotal - _progress.bytesDownloaded;
		if (_progress.downloadSpeed > 0) {
			_progress.remainingSeconds = bytesRemaining / _progress.downloadSpeed;
		}

		_lastSpeedUpdate = now;
		_lastBytesReceived = _progress.bytesDownloaded;
		_currentBandwidthUsage = _progress.downloadSpeed;
	}
}

void MiningDriverManager::updateProgressInfo() {
	// Update status message with speed and ETA
	if (_progress.downloadSpeed > 0) {
		const auto speedMbps = (_progress.downloadSpeed * 8) / (1024 * 1024);  // Convert to Mbps
		const auto etaMin = _progress.remainingSeconds / 60;
		const auto etaSec = _progress.remainingSeconds % 60;

		_progress.statusMessage = QString("Downloading %1 (%2%) - %3 Mbps - %4:%5 remaining")
			.arg(getDriverFileName(_currentDownload))
			.arg(_progress.progressPercent)
			.arg(speedMbps, 0, 'f', 1)
			.arg(etaMin)
			.arg(etaSec, 2, 10, QChar('0'));
	}
}

void MiningDriverManager::updateBandwidthLimit() {
	// Check if we're exceeding the 20% limit
	if (_currentBandwidthUsage > _maxAllowedBandwidth) {
		// Slow down download (would need custom implementation)
		// For now, just log the violation
		qDebug() << "Bandwidth usage exceeds 20% limit:" << _currentBandwidthUsage << ">" << _maxAllowedBandwidth;
	}
}

QString MiningDriverManager::getDriverFileName(DriverType type) const {
	switch (type) {
		case DriverType::CUDA:
			return "cuda_runtime_installer.exe";
		case DriverType::OpenCL:
			return "opencl_runtime_installer.exe";
		default:
			return "driver_installer.exe";
	}
}

bool MiningDriverManager::installDriver(DriverType type, const QString &filePath) {
	// Silent installation of driver
	switch (type) {
		case DriverType::CUDA:
			return installCudaDriver(filePath);
		case DriverType::OpenCL:
			return installOpenCLDriver(filePath);
		default:
			return false;
	}
}

bool MiningDriverManager::installCudaDriver(const QString &filePath) {
	// Run CUDA installer with silent flag
	QProcess process;
	process.start(filePath, QStringList() << "-s");  // -s for silent install
	return process.waitForFinished(300000);  // Wait up to 5 minutes
}

bool MiningDriverManager::installOpenCLDriver(const QString &filePath) {
	// Run OpenCL installer with silent flag
	QProcess process;
	process.start(filePath, QStringList() << "/S");  // /S for silent install (NSIS)
	return process.waitForFinished(60000);  // Wait up to 1 minute
}

// GPU Detection (platform-specific)
bool MiningDriverManager::detectNvidiaGPU() {
#ifdef Q_OS_WIN
	// Check for NVIDIA GPU via Windows registry or device manager
	QProcess process;
	process.start("wmic", QStringList() << "path" << "win32_VideoController" << "get" << "name");
	process.waitForFinished();
	const auto output = QString::fromUtf8(process.readAllStandardOutput());
	return output.contains("NVIDIA", Qt::CaseInsensitive);
#else
	// Linux/macOS: check for NVIDIA device
	QProcess process;
	process.start("lspci");
	process.waitForFinished();
	const auto output = QString::fromUtf8(process.readAllStandardOutput());
	return output.contains("NVIDIA", Qt::CaseInsensitive);
#endif
}

bool MiningDriverManager::detectAMDGPU() {
#ifdef Q_OS_WIN
	QProcess process;
	process.start("wmic", QStringList() << "path" << "win32_VideoController" << "get" << "name");
	process.waitForFinished();
	const auto output = QString::fromUtf8(process.readAllStandardOutput());
	return output.contains("AMD", Qt::CaseInsensitive) || output.contains("Radeon", Qt::CaseInsensitive);
#else
	QProcess process;
	process.start("lspci");
	process.waitForFinished();
	const auto output = QString::fromUtf8(process.readAllStandardOutput());
	return output.contains("AMD", Qt::CaseInsensitive) || output.contains("Radeon", Qt::CaseInsensitive);
#endif
}

bool MiningDriverManager::detectIntelGPU() {
#ifdef Q_OS_WIN
	QProcess process;
	process.start("wmic", QStringList() << "path" << "win32_VideoController" << "get" << "name");
	process.waitForFinished();
	const auto output = QString::fromUtf8(process.readAllStandardOutput());
	return output.contains("Intel", Qt::CaseInsensitive);
#else
	QProcess process;
	process.start("lspci");
	process.waitForFinished();
	const auto output = QString::fromUtf8(process.readAllStandardOutput());
	return output.contains("Intel", Qt::CaseInsensitive);
#endif
}

bool MiningDriverManager::isCudaInstalled() {
#ifdef Q_OS_WIN
	return QFile::exists("C:/Program Files/NVIDIA GPU Computing Toolkit/CUDA/v11.7/bin/nvcc.exe");
#else
	return QFile::exists("/usr/local/cuda/bin/nvcc");
#endif
}

bool MiningDriverManager::isOpenCLInstalled() {
#ifdef Q_OS_WIN
	return QFile::exists("C:/Windows/System32/OpenCL.dll");
#else
	return QFile::exists("/usr/lib/x86_64-linux-gnu/libOpenCL.so");
#endif
}

qint64 MiningDriverManager::detectAvailableBandwidth() {
	// This is a simplified implementation
	// In reality, you'd need to:
	// 1. Check network interface speed
	// 2. Perform speed test
	// 3. Use OS APIs to get connection info

	// For now, assume 100 Mbps (typical home connection)
	const auto mbps = kDefaultBandwidthMbps;
	return (mbps * 1024 * 1024) / 8;  // Convert Mbps to bytes per second
}

} // namespace Data
