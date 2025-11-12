/*
This file is part of SpyGram Desktop,
the privacy-enhanced desktop application for secure messaging.

For license and copyright information please follow this link:
https://github.com/SWORDIntel/SpyGram/blob/main/LEGAL
*/
#include "data/data_network_security.h"

#include "data/data_session.h"
#include "data/data_signal_protocol.h"
#include "base/random.h"
#include "base/openssl_help.h"

#include <QtCore/QTimer>
#include <QtCore/QThread>
#include <QtNetwork/QTcpSocket>
#include <QtNetwork/QUdpSocket>
#include <QtNetwork/QNetworkInterface>
#include <QtWebSockets/QWebSocket>

#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/kdf.h>

namespace Data {
namespace {

// Mesh networking constants
constexpr auto kMaxMeshNodes = 100;
constexpr auto kOptimalMeshNodes = 10;
constexpr auto kMeshHeartbeatInterval = 30000; // 30 seconds
constexpr auto kNodeDiscoveryTimeout = 5000;   // 5 seconds
constexpr auto kMaxRoutingHops = 6;
constexpr auto kBridgeSelectionInterval = 60000; // 1 minute

// Bridge networking constants
constexpr auto kMaxBridges = 50;
constexpr auto kBridgeHealthCheckInterval = 120000; // 2 minutes
constexpr auto kBridgeRotationInterval = 300000;    // 5 minutes
constexpr auto kBridgeConnectionTimeout = 10000;    // 10 seconds

// Protocol identifiers
constexpr auto kMeshProtocolVersion = 1;
constexpr auto kBridgeProtocolVersion = 1;

} // namespace

// Bridge Manager Implementation
class NetworkSecurity::BridgeManager : public QObject {
    Q_OBJECT

public:
    explicit BridgeManager(NetworkSecurityTier tier, QObject *parent = nullptr)
        : QObject(parent)
        , _tier(tier)
        , _healthCheckTimer(new QTimer(this))
        , _rotationTimer(new QTimer(this)) {
        _initializeBridgeManager();
    }

    NetworkSecurityResult addBridge(const BridgeConfiguration &bridge) {
        if (_bridges.size() >= kMaxBridges) {
            return NetworkSecurityResult::BridgeConnectionFailed;
        }

        if (_bridges.contains(bridge.bridgeId)) {
            return NetworkSecurityResult::BridgeConnectionFailed;
        }

        _bridges[bridge.bridgeId] = bridge;

        // Test bridge connectivity
        if (_testBridgeConnectivity(bridge)) {
            _bridges[bridge.bridgeId].isActive = true;
            _bridges[bridge.bridgeId].lastActive = QDateTime::currentDateTime();
            emit bridgeAdded(bridge.bridgeId);
            return NetworkSecurityResult::Success;
        } else {
            _bridges.remove(bridge.bridgeId);
            return NetworkSecurityResult::BridgeConnectionFailed;
        }
    }

    NetworkSecurityResult removeBridge(const QString &bridgeId) {
        if (!_bridges.contains(bridgeId)) {
            return NetworkSecurityResult::BridgeConnectionFailed;
        }

        _bridges.remove(bridgeId);
        emit bridgeRemoved(bridgeId);
        return NetworkSecurityResult::Success;
    }

    QVector<BridgeConfiguration> getActiveBridges() const {
        QVector<BridgeConfiguration> activeBridges;
        for (const auto &bridge : _bridges) {
            if (bridge.isActive) {
                activeBridges.append(bridge);
            }
        }
        return activeBridges;
    }

    base::expected<BridgeConfiguration, NetworkSecurityResult> selectOptimalBridge() {
        auto activeBridges = getActiveBridges();
        if (activeBridges.isEmpty()) {
            return NetworkSecurityResult::BridgeConnectionFailed;
        }

        // Sort bridges by reliability and latency
        std::sort(activeBridges.begin(), activeBridges.end(),
            [](const BridgeConfiguration &a, const BridgeConfiguration &b) {
                if (std::abs(a.reliability - b.reliability) > 0.1f) {
                    return a.reliability > b.reliability;
                }
                // If reliability is similar, prefer more recent activity
                return a.lastActive > b.lastActive;
            });

        return activeBridges.first();
    }

    void startHealthMonitoring() {
        connect(_healthCheckTimer, &QTimer::timeout,
                this, &BridgeManager::_performHealthChecks);
        _healthCheckTimer->start(kBridgeHealthCheckInterval);

        connect(_rotationTimer, &QTimer::timeout,
                this, &BridgeManager::_rotateBridges);
        _rotationTimer->start(kBridgeRotationInterval);
    }

    void stopHealthMonitoring() {
        _healthCheckTimer->stop();
        _rotationTimer->stop();
    }

signals:
    void bridgeAdded(const QString &bridgeId);
    void bridgeRemoved(const QString &bridgeId);
    void bridgeStatusChanged(const QString &bridgeId, bool active);
    void optimalBridgeChanged(const QString &bridgeId);

private slots:
    void _performHealthChecks() {
        for (auto &bridge : _bridges) {
            const bool isHealthy = _testBridgeConnectivity(bridge);
            if (bridge.isActive != isHealthy) {
                bridge.isActive = isHealthy;
                bridge.lastActive = QDateTime::currentDateTime();
                emit bridgeStatusChanged(bridge.bridgeId, isHealthy);
            }

            // Update reliability score based on health checks
            _updateReliabilityScore(bridge, isHealthy);
        }
    }

    void _rotateBridges() {
        // Implement bridge rotation for enhanced security
        auto activeBridges = getActiveBridges();
        if (activeBridges.size() > 1) {
            // Select new optimal bridge
            auto optimalBridge = selectOptimalBridge();
            if (optimalBridge) {
                emit optimalBridgeChanged(optimalBridge->bridgeId);
            }
        }
    }

private:
    NetworkSecurityTier _tier;
    QHash<QString, BridgeConfiguration> _bridges;
    QTimer *_healthCheckTimer;
    QTimer *_rotationTimer;

    void _initializeBridgeManager() {
        // Load default bridges based on tier
        _loadDefaultBridges();
        startHealthMonitoring();
    }

    void _loadDefaultBridges() {
        // Tier-specific default bridges
        switch (_tier) {
        case NetworkSecurityTier::Tier0_Quantum:
        case NetworkSecurityTier::Tier1_Premium:
            _addDefaultBridge("obfs4", "bridge1.spygram.net", 443, "premium");
            _addDefaultBridge("meek", "bridge2.spygram.net", 80, "premium");
            [[fallthrough]];
        case NetworkSecurityTier::Tier2_Enhanced:
            _addDefaultBridge("obfs4", "bridge3.spygram.net", 8080, "enhanced");
            [[fallthrough]];
        case NetworkSecurityTier::Tier3_Standard:
            _addDefaultBridge("vanilla", "bridge4.spygram.net", 9001, "standard");
            [[fallthrough]];
        case NetworkSecurityTier::Tier4_Universal:
            _addDefaultBridge("vanilla", "bridge5.spygram.net", 9002, "universal");
            break;
        }
    }

    void _addDefaultBridge(const QString &type, const QString &address,
                          uint16 port, const QString &tier) {
        BridgeConfiguration bridge;
        bridge.bridgeId = QString("%1_%2_%3").arg(type, address, tier);
        bridge.bridgeAddress = address;
        bridge.bridgePort = port;
        bridge.bridgeType = type;
        bridge.reliability = 0.8f; // Default reliability
        bridge.lastActive = QDateTime::currentDateTime();

        // Generate bridge key
        bridge.bridgeKey.resize(32);
        base::RandomFill(bridge.bridgeKey);

        _bridges[bridge.bridgeId] = bridge;
    }

    bool _testBridgeConnectivity(const BridgeConfiguration &bridge) {
        // Test bridge connectivity based on type
        if (bridge.bridgeType == "obfs4") {
            return _testObfs4Bridge(bridge);
        } else if (bridge.bridgeType == "meek") {
            return _testMeekBridge(bridge);
        } else if (bridge.bridgeType == "snowflake") {
            return _testSnowflakeBridge(bridge);
        } else {
            return _testVanillaBridge(bridge);
        }
    }

    bool _testObfs4Bridge(const BridgeConfiguration &bridge) {
        // Test obfs4 bridge connectivity
        QTcpSocket socket;
        socket.connectToHost(bridge.bridgeAddress, bridge.bridgePort);

        if (!socket.waitForConnected(kBridgeConnectionTimeout)) {
            return false;
        }

        // Send obfs4 handshake
        const QByteArray handshake = _createObfs4Handshake(bridge);
        socket.write(handshake);
        socket.waitForBytesWritten(1000);

        // Wait for response
        if (socket.waitForReadyRead(2000)) {
            const auto response = socket.readAll();
            return _validateObfs4Response(response, bridge);
        }

        return false;
    }

    bool _testMeekBridge(const BridgeConfiguration &bridge) {
        // Test meek bridge (domain fronting)
        QNetworkAccessManager manager;
        QNetworkRequest request;
        request.setUrl(QUrl(QString("https://%1/").arg(bridge.bridgeAddress)));
        request.setHeader(QNetworkRequest::UserAgentHeader,
                         "Mozilla/5.0 (compatible; SpyGram)");

        auto reply = manager.get(request);
        QTimer timer;
        timer.setSingleShot(true);

        QEventLoop loop;
        connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
        connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);
        timer.start(kBridgeConnectionTimeout);

        loop.exec();

        const bool success = (reply->error() == QNetworkReply::NoError);
        reply->deleteLater();
        return success;
    }

    bool _testSnowflakeBridge(const BridgeConfiguration &bridge) {
        // Test snowflake bridge (WebRTC-based)
        // This would integrate with WebRTC for actual implementation
        return true; // Placeholder
    }

    bool _testVanillaBridge(const BridgeConfiguration &bridge) {
        // Test basic TCP connectivity
        QTcpSocket socket;
        socket.connectToHost(bridge.bridgeAddress, bridge.bridgePort);
        return socket.waitForConnected(kBridgeConnectionTimeout);
    }

    QByteArray _createObfs4Handshake(const BridgeConfiguration &bridge) {
        // Create obfs4 handshake packet
        QByteArray handshake;
        handshake.append(static_cast<char>(kBridgeProtocolVersion));
        handshake.append(bridge.bridgeKey.data(), std::min(32, int(bridge.bridgeKey.size())));

        // Add timestamp
        const auto timestamp = QDateTime::currentMSecsSinceEpoch();
        handshake.append(reinterpret_cast<const char*>(&timestamp), sizeof(timestamp));

        return handshake;
    }

    bool _validateObfs4Response(const QByteArray &response, const BridgeConfiguration &bridge) {
        // Validate obfs4 bridge response
        if (response.size() < 16) return false;

        // Check protocol version
        if (static_cast<uint8>(response[0]) != kBridgeProtocolVersion) {
            return false;
        }

        // Additional validation logic would go here
        return true;
    }

    void _updateReliabilityScore(BridgeConfiguration &bridge, bool healthCheckPassed) {
        const float adjustment = healthCheckPassed ? 0.01f : -0.05f;
        bridge.reliability = std::clamp(bridge.reliability + adjustment, 0.0f, 1.0f);
    }
};

// Mesh Network Manager Implementation
class NetworkSecurity::MeshNetworkManager : public QObject {
    Q_OBJECT

public:
    explicit MeshNetworkManager(NetworkSecurityTier tier, QObject *parent = nullptr)
        : QObject(parent)
        , _tier(tier)
        , _isConnected(false)
        , _discoverySocket(new QUdpSocket(this))
        , _heartbeatTimer(new QTimer(this)) {
        _initializeMeshManager();
    }

    NetworkSecurityResult joinMeshNetwork() {
        if (_isConnected) {
            return NetworkSecurityResult::Success;
        }

        try {
            // Generate node identity
            _generateNodeIdentity();

            // Start node discovery
            if (!_startNodeDiscovery()) {
                return NetworkSecurityResult::MeshNetworkFailed;
            }

            // Start heartbeat mechanism
            _startHeartbeat();

            _isConnected = true;
            emit meshNetworkJoined(_nodes.size());
            return NetworkSecurityResult::Success;

        } catch (...) {
            return NetworkSecurityResult::MeshNetworkFailed;
        }
    }

    NetworkSecurityResult leaveMeshNetwork() {
        if (!_isConnected) {
            return NetworkSecurityResult::Success;
        }

        // Send disconnect notification to all nodes
        _broadcastDisconnect();

        // Stop all timers and connections
        _heartbeatTimer->stop();
        _discoverySocket->close();

        // Clear node list
        _nodes.clear();

        _isConnected = false;
        emit meshNetworkLeft();
        return NetworkSecurityResult::Success;
    }

    QVector<MeshNetworkNode> getMeshNodes() const {
        QVector<MeshNetworkNode> nodeList;
        for (const auto &node : _nodes) {
            nodeList.append(node);
        }
        return nodeList;
    }

    base::expected<QVector<QString>, NetworkSecurityResult> findOptimalRoute(
            const QString &destination) {
        if (!_isConnected || _nodes.isEmpty()) {
            return NetworkSecurityResult::MeshNetworkFailed;
        }

        // Implement shortest path routing algorithm
        auto route = _calculateOptimalRoute(destination);
        if (route.isEmpty()) {
            return NetworkSecurityResult::MeshNetworkFailed;
        }

        return route;
    }

    bool isConnected() const {
        return _isConnected;
    }

    int getNodeCount() const {
        return _nodes.size();
    }

signals:
    void meshNetworkJoined(int nodeCount);
    void meshNetworkLeft();
    void nodeDiscovered(const QString &nodeId);
    void nodeDisconnected(const QString &nodeId);
    void routeCalculated(const QVector<QString> &route);

private slots:
    void _handleNodeDiscovery() {
        // Handle incoming node discovery packets
        while (_discoverySocket->hasPendingDatagrams()) {
            QByteArray datagram;
            datagram.resize(_discoverySocket->pendingDatagramSize());
            QHostAddress sender;
            quint16 senderPort;

            _discoverySocket->readDatagram(datagram.data(), datagram.size(),
                                         &sender, &senderPort);

            _processDiscoveryPacket(datagram, sender, senderPort);
        }
    }

    void _sendHeartbeat() {
        // Send heartbeat to all connected nodes
        for (const auto &node : _nodes) {
            _sendHeartbeatToNode(node);
        }

        // Clean up inactive nodes
        _cleanupInactiveNodes();
    }

private:
    NetworkSecurityTier _tier;
    bool _isConnected;
    QHash<QString, MeshNetworkNode> _nodes;
    QUdpSocket *_discoverySocket;
    QTimer *_heartbeatTimer;

    // Node identity
    QString _nodeId;
    bytes::vector _nodePrivateKey;
    bytes::vector _nodePublicKey;

    void _initializeMeshManager() {
        // Setup discovery socket
        connect(_discoverySocket, &QUdpSocket::readyRead,
                this, &MeshNetworkManager::_handleNodeDiscovery);

        // Setup heartbeat timer
        connect(_heartbeatTimer, &QTimer::timeout,
                this, &MeshNetworkManager::_sendHeartbeat);
    }

    void _generateNodeIdentity() {
        // Generate unique node ID
        _nodeId = QString("node_%1_%2")
            .arg(QDateTime::currentMSecsSinceEpoch())
            .arg(QRandomGenerator::global()->generate());

        // Generate ECDH key pair for secure communication
        _generateECDHKeyPair();
    }

    void _generateECDHKeyPair() {
        // Generate P-256 key pair
        _nodePrivateKey.resize(32);
        _nodePublicKey.resize(65); // Uncompressed point

        EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if (!key) return;

        auto cleanup = gsl::finally([&] { EC_KEY_free(key); });

        if (EC_KEY_generate_key(key) != 1) return;

        // Extract private key
        const BIGNUM *priv = EC_KEY_get0_private_key(key);
        BN_bn2binpad(priv, _nodePrivateKey.data(), _nodePrivateKey.size());

        // Extract public key
        const EC_POINT *pub = EC_KEY_get0_public_key(key);
        const EC_GROUP *group = EC_KEY_get0_group(key);

        EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED,
                          _nodePublicKey.data(), _nodePublicKey.size(), nullptr);
    }

    bool _startNodeDiscovery() {
        // Bind to discovery port
        const quint16 discoveryPort = 25519 + (_tier * 100);
        if (!_discoverySocket->bind(QHostAddress::Any, discoveryPort)) {
            return false;
        }

        // Broadcast discovery packet
        _broadcastDiscovery();

        return true;
    }

    void _broadcastDiscovery() {
        // Create discovery packet
        QByteArray packet;
        QDataStream stream(&packet, QIODevice::WriteOnly);

        stream << static_cast<quint8>(kMeshProtocolVersion);
        stream << static_cast<quint8>(0x01); // Discovery packet type
        stream << _nodeId;
        stream << QByteArray(_nodePublicKey.data(), _nodePublicKey.size());
        stream << static_cast<quint64>(QDateTime::currentMSecsSinceEpoch());

        // Broadcast to local network
        _discoverySocket->writeDatagram(packet, QHostAddress::Broadcast, 25519);

        // Also try multicast
        const QHostAddress multicastAddr("239.255.25.19");
        _discoverySocket->writeDatagram(packet, multicastAddr, 25519);
    }

    void _processDiscoveryPacket(const QByteArray &packet,
                                const QHostAddress &sender,
                                quint16 senderPort) {
        QDataStream stream(packet);

        quint8 version, packetType;
        QString nodeId;
        QByteArray publicKey;
        quint64 timestamp;

        stream >> version >> packetType >> nodeId >> publicKey >> timestamp;

        if (version != kMeshProtocolVersion || nodeId == _nodeId) {
            return; // Invalid or own packet
        }

        // Create or update node
        MeshNetworkNode node;
        node.nodeId = nodeId;
        node.nodeAddress = sender.toString();
        node.nodePort = senderPort;
        node.nodePublicKey = bytes::vector(publicKey.begin(), publicKey.end());
        node.lastSeen = QDateTime::currentDateTime();
        node.trustLevel = _calculateTrustLevel(node);
        node.hopDistance = 1; // Direct connection

        if (!_nodes.contains(nodeId)) {
            _nodes[nodeId] = node;
            emit nodeDiscovered(nodeId);
        } else {
            _nodes[nodeId].lastSeen = node.lastSeen;
        }

        // Send response if this was a discovery
        if (packetType == 0x01) {
            _sendDiscoveryResponse(sender, senderPort);
        }
    }

    void _sendDiscoveryResponse(const QHostAddress &target, quint16 port) {
        QByteArray packet;
        QDataStream stream(&packet, QIODevice::WriteOnly);

        stream << static_cast<quint8>(kMeshProtocolVersion);
        stream << static_cast<quint8>(0x02); // Discovery response
        stream << _nodeId;
        stream << QByteArray(_nodePublicKey.data(), _nodePublicKey.size());
        stream << static_cast<quint64>(QDateTime::currentMSecsSinceEpoch());

        _discoverySocket->writeDatagram(packet, target, port);
    }

    void _startHeartbeat() {
        _heartbeatTimer->start(kMeshHeartbeatInterval);
    }

    void _sendHeartbeatToNode(const MeshNetworkNode &node) {
        QByteArray packet;
        QDataStream stream(&packet, QIODevice::WriteOnly);

        stream << static_cast<quint8>(kMeshProtocolVersion);
        stream << static_cast<quint8>(0x03); // Heartbeat packet
        stream << _nodeId;
        stream << static_cast<quint64>(QDateTime::currentMSecsSinceEpoch());

        const QHostAddress nodeAddr(node.nodeAddress);
        _discoverySocket->writeDatagram(packet, nodeAddr, node.nodePort);
    }

    void _cleanupInactiveNodes() {
        const auto cutoffTime = QDateTime::currentDateTime().addSecs(-300); // 5 minutes

        auto it = _nodes.begin();
        while (it != _nodes.end()) {
            if (it->lastSeen < cutoffTime) {
                emit nodeDisconnected(it->nodeId);
                it = _nodes.erase(it);
            } else {
                ++it;
            }
        }
    }

    void _broadcastDisconnect() {
        QByteArray packet;
        QDataStream stream(&packet, QIODevice::WriteOnly);

        stream << static_cast<quint8>(kMeshProtocolVersion);
        stream << static_cast<quint8>(0x04); // Disconnect packet
        stream << _nodeId;

        for (const auto &node : _nodes) {
            const QHostAddress nodeAddr(node.nodeAddress);
            _discoverySocket->writeDatagram(packet, nodeAddr, node.nodePort);
        }
    }

    float _calculateTrustLevel(const MeshNetworkNode &node) {
        // Calculate trust level based on various factors
        float trust = 0.5f; // Base trust

        // Factor in connection age (longer = more trusted)
        const auto ageMinutes = QDateTime::currentDateTime()
            .secsTo(node.lastSeen) / 60.0;
        trust += std::min(0.3f, float(ageMinutes) / 1440.0f); // Max bonus for 24h

        // Factor in network position
        if (node.hopDistance == 1) {
            trust += 0.1f; // Direct connection bonus
        }

        return std::clamp(trust, 0.0f, 1.0f);
    }

    QVector<QString> _calculateOptimalRoute(const QString &destination) {
        // Implement Dijkstra's algorithm for shortest path
        QVector<QString> route;

        // For now, return direct route if possible
        if (_nodes.contains(destination)) {
            route.append(destination);
            return route;
        }

        // Find multi-hop route
        // [Implement full routing algorithm]

        return route;
    }
};

// Add these implementations to the main NetworkSecurity class methods
NetworkSecurityResult NetworkSecurity::addBridge(const BridgeConfiguration &bridge) {
    if (!_initialized || !_bridgeManager) {
        return NetworkSecurityResult::InitializationFailed;
    }
    return _bridgeManager->addBridge(bridge);
}

NetworkSecurityResult NetworkSecurity::removeBridge(const QString &bridgeId) {
    if (!_initialized || !_bridgeManager) {
        return NetworkSecurityResult::InitializationFailed;
    }
    return _bridgeManager->removeBridge(bridgeId);
}

QVector<BridgeConfiguration> NetworkSecurity::getActiveBridges() const {
    if (!_initialized || !_bridgeManager) {
        return {};
    }
    return _bridgeManager->getActiveBridges();
}

base::expected<BridgeConfiguration, NetworkSecurityResult> NetworkSecurity::selectOptimalBridge() {
    if (!_initialized || !_bridgeManager) {
        return NetworkSecurityResult::InitializationFailed;
    }
    return _bridgeManager->selectOptimalBridge();
}

NetworkSecurityResult NetworkSecurity::joinMeshNetwork() {
    if (!_initialized || !_meshManager) {
        return NetworkSecurityResult::InitializationFailed;
    }
    return _meshManager->joinMeshNetwork();
}

NetworkSecurityResult NetworkSecurity::leaveMeshNetwork() {
    if (!_initialized || !_meshManager) {
        return NetworkSecurityResult::InitializationFailed;
    }
    return _meshManager->leaveMeshNetwork();
}

QVector<MeshNetworkNode> NetworkSecurity::getMeshNodes() const {
    if (!_initialized || !_meshManager) {
        return {};
    }
    return _meshManager->getMeshNodes();
}

base::expected<QVector<QString>, NetworkSecurityResult> NetworkSecurity::findOptimalRoute(
        const QString &destination) {
    if (!_initialized || !_meshManager) {
        return NetworkSecurityResult::InitializationFailed;
    }
    return _meshManager->findOptimalRoute(destination);
}

// Update the initializeNetworkComponents method to include mesh components
void NetworkSecurity::initializeNetworkComponents() {
    _obfuscator = std::make_unique<TrafficObfuscator>(_currentTier);
    _dpiEvasion = std::make_unique<DPIEvasion>(_currentTier);
    _bridgeManager = std::make_unique<BridgeManager>(_currentTier);
    _meshManager = std::make_unique<MeshNetworkManager>(_currentTier);

    // Connect signals for bridge and mesh status updates
    if (_bridgeManager) {
        connect(_bridgeManager.get(), &BridgeManager::bridgeStatusChanged,
                this, [this](const QString &bridgeId, bool connected) {
                    emit bridgeConnectionStatusChanged(bridgeId, connected);
                });
    }

    if (_meshManager) {
        connect(_meshManager.get(), &MeshNetworkManager::meshNetworkJoined,
                this, [this](int nodeCount) {
                    emit meshNetworkStatusChanged(true, nodeCount);
                });
        connect(_meshManager.get(), &MeshNetworkManager::meshNetworkLeft,
                this, [this]() {
                    emit meshNetworkStatusChanged(false, 0);
                });
    }
}

} // namespace Data

#include "data_network_mesh.moc"