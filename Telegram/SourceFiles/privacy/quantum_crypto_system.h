#pragma once

#include <QtCore/QObject>
#include <memory>

class QuantumCryptoSystem : public QObject {
public:
    explicit QuantumCryptoSystem(QObject *parent = nullptr) : QObject(parent) {}
    ~QuantumCryptoSystem() = default;

    bool initialize() { return true; }
    bool isAvailable() const { return true; }
};
