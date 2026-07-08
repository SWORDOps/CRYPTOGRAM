/*
This file is part of CRYPTOGRAM,
the most advanced secure messaging application.

For license and copyright information please follow this link:
https://github.com/SWORDOps/CRYPTOGRAM/blob/main/LICENSE
*/
#include "data/data_i2p_integration.h"

#include <QtCore/QRandomGenerator>
#include <QtCore/QStringList>
#include <QtCore/QUrl>
#include <QtNetwork/QHostAddress>

namespace Data {

I2PIntegration::I2PIntegration(Session *session)
: _session(session)
, _samSocket(new QTcpSocket(this))
, _statusCheckTimer(new QTimer(this))
, _reconnectTimer(new QTimer(this)) {
    _statusCheckTimer->setInterval(10000);
    _reconnectTimer->setInterval(5000);
    _reconnectTimer->setSingleShot(true);

    connect(_samSocket, &QTcpSocket::connected, this, &I2PIntegration::handleRouterConnection);
    connect(_samSocket, &QTcpSocket::disconnected, this, &I2PIntegration::handleRouterDisconnection);
    connect(_samSocket, &QTcpSocket::readyRead, this, &I2PIntegration::handleTunnelData);
    connect(_statusCheckTimer, &QTimer::timeout, this, &I2PIntegration::checkRouterStatus);
    connect(_reconnectTimer, &QTimer::timeout, this, [this] {
        if (_enabled && !_routerInfo.routerAddress.isEmpty()) {
            connectToRouter(_routerInfo.routerAddress, _routerInfo.routerPort);
        }
    });
}

I2PIntegration::~I2PIntegration() {
    shutdown();
}

bool I2PIntegration::initialize() {
    if (_initialized) {
        return true;
    }

    _sessionId = generateSessionId();
    _initialized = true;
    _status = I2PStatus::Disconnected;
    _routerInfo.routerAddress = "127.0.0.1";
    _routerInfo.routerPort = 7656;

    _statusCheckTimer->start();
    return true;
}

void I2PIntegration::shutdown() {
    if (!_initialized) {
        return;
    }

    for (auto it = _tunnelSockets.begin(); it != _tunnelSockets.end(); ++it) {
        if (it.value()) {
            it.value()->disconnectFromHost();
            it.value()->deleteLater();
        }
    }
    _tunnelSockets.clear();
    _tunnels.clear();

    disconnectFromRouter();
    _statusCheckTimer->stop();
    _reconnectTimer->stop();
    _initialized = false;
}

bool I2PIntegration::connectToRouter(const QString &address, uint16 port) {
    if (!_initialized) {
        return false;
    }

    _routerInfo.routerAddress = address;
    _routerInfo.routerPort = port;
    _status = I2PStatus::Connecting;
    Q_EMIT statusChanged(_status);

    _samSocket->abort();
    _samSocket->connectToHost(address, port);
    if (!_samSocket->waitForConnected(2500)) {
        _status = I2PStatus::RouterNotFound;
        _routerInfo.isRunning = false;
        Q_EMIT statusChanged(_status);
        Q_EMIT error(QString("I2P router not reachable at %1:%2").arg(address).arg(port));
        return false;
    }

    _routerInfo.isRunning = true;
    _status = I2PStatus::Connected;
    _routerInfo.version = "SAM";
    Q_EMIT statusChanged(_status);
    Q_EMIT routerConnected();
    return true;
}

bool I2PIntegration::disconnectFromRouter() {
    if (_samSocket->state() != QAbstractSocket::UnconnectedState) {
        _samSocket->disconnectFromHost();
        if (_samSocket->state() != QAbstractSocket::UnconnectedState) {
            _samSocket->waitForDisconnected(1000);
        }
    }

    _routerInfo.isRunning = false;
    _status = I2PStatus::Disconnected;
    Q_EMIT statusChanged(_status);
    Q_EMIT routerDisconnected();
    return true;
}

QString I2PIntegration::createTunnel(const I2PTunnelConfig &config) {
    if (!_initialized) {
        return {};
    }

    auto tunnel = config;
    if (tunnel.tunnelId.isEmpty()) {
        tunnel.tunnelId = QString("i2p-%1").arg(generateSessionId());
    }

    _tunnels[tunnel.tunnelId] = tunnel;
    _statistics.tunnelsCreated++;
    _statistics.lastActivity = QDateTime::currentDateTime();

    Q_EMIT tunnelCreated(tunnel.tunnelId);
    return tunnel.tunnelId;
}

bool I2PIntegration::destroyTunnel(const QString &tunnelId) {
    if (!_tunnels.contains(tunnelId)) {
        return false;
    }

    if (auto socketIt = _tunnelSockets.find(tunnelId); socketIt != _tunnelSockets.end()) {
        if (socketIt.value()) {
            socketIt.value()->disconnectFromHost();
            socketIt.value()->deleteLater();
        }
        _tunnelSockets.erase(socketIt);
    }

    _tunnels.remove(tunnelId);
    Q_EMIT tunnelDestroyed(tunnelId);
    return true;
}

bool I2PIntegration::startTunnel(const QString &tunnelId) {
    auto it = _tunnels.find(tunnelId);
    if (it == _tunnels.end()) {
        return false;
    }
    it->autoStart = true;
    _status = I2PStatus::Tunneling;
    Q_EMIT statusChanged(_status);
    return true;
}

bool I2PIntegration::stopTunnel(const QString &tunnelId) {
    auto it = _tunnels.find(tunnelId);
    if (it == _tunnels.end()) {
        return false;
    }
    it->autoStart = false;
    if (_tunnels.isEmpty()) {
        _status = I2PStatus::Connected;
        Q_EMIT statusChanged(_status);
    }
    return true;
}

QVector<I2PTunnelConfig> I2PIntegration::getActiveTunnels() const {
    QVector<I2PTunnelConfig> result;
    result.reserve(_tunnels.size());
    for (auto it = _tunnels.begin(); it != _tunnels.end(); ++it) {
        result.push_back(it.value());
    }
    return result;
}

QString I2PIntegration::createDestination() {
    QByteArray bytes(32, Qt::Uninitialized);
    QRandomGenerator::global()->fillRange(reinterpret_cast<quint32*>(bytes.data()), 8);
    return QString::fromLatin1(bytes.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
}

QString I2PIntegration::getDestination(const QString &tunnelId) const {
    const auto it = _tunnels.find(tunnelId);
    return (it == _tunnels.end()) ? QString() : it->destination;
}

bool I2PIntegration::isDestinationValid(const QString &destination) const {
    return !destination.trimmed().isEmpty() && destination.size() >= 32;
}

bool I2PIntegration::sendData(const QString &tunnelId, const QByteArray &data) {
    if (!_tunnels.contains(tunnelId) || data.isEmpty()) {
        return false;
    }

    _statistics.bytesSent += data.size();
    _statistics.lastActivity = QDateTime::currentDateTime();

    Q_EMIT dataReceived(tunnelId, data);
    return true;
}

QByteArray I2PIntegration::receiveData(const QString &tunnelId) {
    auto it = _tunnelSockets.find(tunnelId);
    if (it == _tunnelSockets.end() || !it.value()) {
        return {};
    }
    const auto data = it.value()->readAll();
    _statistics.bytesReceived += data.size();
    _statistics.lastActivity = QDateTime::currentDateTime();
    return data;
}

void I2PIntegration::setEnabled(bool enabled) {
    _enabled = enabled;
    if (!_enabled) {
        disconnectFromRouter();
    } else if (_initialized && _routerInfo.routerAddress.isEmpty()) {
        _routerInfo.routerAddress = "127.0.0.1";
        _routerInfo.routerPort = 7656;
    }
}

void I2PIntegration::resetStatistics() {
    _statistics = I2PStatistics();
}

bool I2PIntegration::detectI2PRouter() {
    QTcpSocket probe;
    probe.connectToHost(_routerInfo.routerAddress.isEmpty() ? "127.0.0.1" : _routerInfo.routerAddress,
        _routerInfo.routerPort == 0 ? 7656 : _routerInfo.routerPort);
    const auto ok = probe.waitForConnected(800);
    if (ok) {
        probe.disconnectFromHost();
    }
    _routerInfo.isRunning = ok;
    if (!ok && _status == I2PStatus::Connected) {
        _status = I2PStatus::RouterNotFound;
        Q_EMIT statusChanged(_status);
    }
    return ok;
}

bool I2PIntegration::downloadI2PRouter() {
    Q_EMIT error("I2P router auto-download is not implemented for this build target");
    return false;
}

QString I2PIntegration::getI2PInstallPath() const {
    return QString();
}

void I2PIntegration::handleRouterConnection() {
    _routerInfo.isRunning = true;
    _status = I2PStatus::Connected;
    Q_EMIT statusChanged(_status);
    Q_EMIT routerConnected();
}

void I2PIntegration::handleRouterDisconnection() {
    _routerInfo.isRunning = false;
    _status = I2PStatus::Disconnected;
    Q_EMIT statusChanged(_status);
    Q_EMIT routerDisconnected();

    if (_enabled) {
        _reconnectTimer->start();
    }
}

void I2PIntegration::handleTunnelData() {
    const auto data = _samSocket->readAll();
    if (!data.isEmpty()) {
        _statistics.bytesReceived += data.size();
        _statistics.lastActivity = QDateTime::currentDateTime();
        Q_EMIT dataReceived(QStringLiteral("sam"), data);
    }
}

void I2PIntegration::checkRouterStatus() {
    if (!_initialized || !_enabled) {
        return;
    }

    const auto running = detectI2PRouter();
    if (!running && _samSocket->state() == QAbstractSocket::ConnectedState) {
        _samSocket->disconnectFromHost();
    }
    updateRouterInfo();
    updateStatistics();
}

bool I2PIntegration::sendSAMCommand(const QString &command) {
    if (_samSocket->state() != QAbstractSocket::ConnectedState) {
        return false;
    }
    const auto payload = command.toUtf8() + QByteArray("\n");
    return _samSocket->write(payload) == payload.size() && _samSocket->waitForBytesWritten(1000);
}

QString I2PIntegration::receiveSAMResponse() {
    if (_samSocket->state() != QAbstractSocket::ConnectedState) {
        return {};
    }
    if (!_samSocket->waitForReadyRead(1500)) {
        return {};
    }
    return QString::fromUtf8(_samSocket->readLine()).trimmed();
}

bool I2PIntegration::parseSAMResponse(const QString &response, QString &status, QMap<QString, QString> &params) {
    if (response.isEmpty()) {
        return false;
    }

    const auto parts = response.split(' ', Qt::SkipEmptyParts);
    if (parts.isEmpty()) {
        return false;
    }

    status = parts.front();
    for (int i = 1; i < parts.size(); ++i) {
        const auto eq = parts[i].indexOf('=');
        if (eq <= 0) {
            continue;
        }
        const auto key = parts[i].left(eq).trimmed();
        const auto value = parts[i].mid(eq + 1).trimmed();
        params.insert(key, value);
    }
    return true;
}

void I2PIntegration::updateRouterInfo() {
    _routerInfo.activeTunnels = _tunnels.size();
    _routerInfo.knownPeers = _routerInfo.isRunning ? 1 : 0;
}

void I2PIntegration::updateStatistics() {
    _statistics.currentDestination = _tunnels.isEmpty()
        ? QString()
        : _tunnels.first().destination;
}

QString I2PIntegration::generateSessionId() {
    return QString::number(QDateTime::currentMSecsSinceEpoch(), 16)
        + QString::number(QRandomGenerator::global()->generate(), 16);
}

} // namespace Data
