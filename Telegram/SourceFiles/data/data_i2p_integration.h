/*
This file is part of CRYPTOGRAM,
the most advanced secure messaging application.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LICENSE
*/
#pragma once

#include "base/bytes.h"
#include "base/expected.h"
#include "data/data_network_security.h"

#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QByteArray>
#include <QtCore/QDateTime>
#include <QtNetwork/QTcpSocket>
#include <memory>
#include <vector>

namespace Data {

// Forward declarations
class Session;

// I2P tunnel types
enum class I2PTunnelType {
    Client,         // Outbound I2P client tunnel
    Server,         // Inbound I2P server tunnel
    HTTP,           // HTTP proxy tunnel
    SOCKS,          // SOCKS proxy tunnel
    IRC,            // IRC tunnel
    Streaming       // Generic streaming tunnel
};

// I2P connection status
enum class I2PStatus {
    Disconnected,
    Connecting,
    Connected,
    Tunneling,
    Failed,
    RouterNotFound
};

// I2P tunnel configuration
struct I2PTunnelConfig {
    QString tunnelId;
    I2PTunnelType tunnelType;
    QString destination;        // I2P destination (Base64)
    uint16 localPort = 0;       // Local port for tunnel
    uint16 remotePort = 0;      // Remote port
    int tunnelLength = 3;       // Number of hops (default 3)
    int tunnelQuantity = 2;     // Number of tunnels
    bool autoStart = false;     // Start tunnel automatically
    bool persistent = true;     // Keep tunnel alive
};

// I2P router information
struct I2PRouterInfo {
    QString routerAddress;      // SAM bridge address (default: 127.0.0.1)
    uint16 routerPort = 7656;   // SAM port (default: 7656)
    QString version;            // I2P router version
    int uptime = 0;             // Router uptime in seconds
    int activeTunnels = 0;      // Number of active tunnels
    int knownPeers = 0;         // Number of known routers
    bool isRunning = false;     // Router status
};

// I2P network statistics
struct I2PStatistics {
    qint64 bytesSent = 0;
    qint64 bytesReceived = 0;
    int tunnelsCreated = 0;
    int tunnelsFailed = 0;
    double averageLatency = 0.0;  // ms
    QDateTime lastActivity;
    QString currentDestination;
};

/**
 * I2P Network Integration
 *
 * Provides integration with the Invisible Internet Project (I2P) for anonymous,
 * censorship-resistant communication. I2P creates a fully distributed network
 * layer with end-to-end encryption and garlic routing.
 *
 * Features:
 * - SAM (Simple Anonymous Messaging) protocol support
 * - Multiple tunnel types (client, server, HTTP, SOCKS)
 * - Automatic tunnel management
 * - Garlic routing for anonymity
 * - .i2p address support
 * - Full network layer anonymization
 */
class I2PIntegration : public QObject {
    Q_OBJECT

public:
    explicit I2PIntegration(Session *session);
    ~I2PIntegration();

    // Initialization
    bool initialize();
    bool isInitialized() const { return _initialized; }
    void shutdown();

    // Router management
    bool connectToRouter(const QString &address = "127.0.0.1", uint16 port = 7656);
    bool disconnectFromRouter();
    I2PStatus getStatus() const { return _status; }
    I2PRouterInfo getRouterInfo() const { return _routerInfo; }

    // Tunnel management
    QString createTunnel(const I2PTunnelConfig &config);
    bool destroyTunnel(const QString &tunnelId);
    bool startTunnel(const QString &tunnelId);
    bool stopTunnel(const QString &tunnelId);
    QVector<I2PTunnelConfig> getActiveTunnels() const;

    // Destination management
    QString createDestination();  // Generate new I2P destination
    QString getDestination(const QString &tunnelId) const;
    bool isDestinationValid(const QString &destination) const;

    // Connection
    bool sendData(const QString &tunnelId, const QByteArray &data);
    QByteArray receiveData(const QString &tunnelId);

    // Configuration
    void setEnabled(bool enabled);
    bool isEnabled() const { return _enabled; }
    void setAutoStart(bool autoStart) { _autoStart = autoStart; }
    bool isAutoStart() const { return _autoStart; }

    // Statistics
    I2PStatistics getStatistics() const { return _statistics; }
    void resetStatistics();

    // Network detection
    bool detectI2PRouter();  // Detect if I2P router is running
    bool downloadI2PRouter();  // Download and install I2P router (helper)
    QString getI2PInstallPath() const;

Q_SIGNALS:
    void statusChanged(I2PStatus status);
    void routerConnected();
    void routerDisconnected();
    void tunnelCreated(const QString &tunnelId);
    void tunnelDestroyed(const QString &tunnelId);
    void dataReceived(const QString &tunnelId, const QByteArray &data);
    void error(const QString &error);

private Q_SLOTS:
    void handleRouterConnection();
    void handleRouterDisconnection();
    void handleTunnelData();
    void checkRouterStatus();

private:
    // SAM protocol communication
    bool sendSAMCommand(const QString &command);
    QString receiveSAMResponse();
    bool parseSAMResponse(const QString &response, QString &status, QMap<QString, QString> &params);

    // Internal helpers
    void updateRouterInfo();
    void updateStatistics();
    QString generateSessionId();

    Session *_session = nullptr;
    bool _initialized = false;
    bool _enabled = false;
    bool _autoStart = false;

    I2PStatus _status = I2PStatus::Disconnected;
    I2PRouterInfo _routerInfo;
    I2PStatistics _statistics;

    // SAM bridge connection
    QTcpSocket *_samSocket = nullptr;
    QString _sessionId;

    // Active tunnels
    QMap<QString, I2PTunnelConfig> _tunnels;
    QMap<QString, QTcpSocket*> _tunnelSockets;

    // Timers
    QTimer *_statusCheckTimer = nullptr;
    QTimer *_reconnectTimer = nullptr;
};

} // namespace Data
