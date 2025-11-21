/*
This file is part of SpyGram Desktop,
the privacy-enhanced desktop application for secure messaging.

For license and copyright information please follow this link:
https://github.com/SWORDIntel/SpyGram/blob/main/LEGAL
*/
#pragma once

namespace Data {

// Quantum cryptographic algorithms
enum class QuantumAlgorithm {
    Kyber512,
    Kyber768,
    Kyber1024,
    ML_KEM_512,
    ML_KEM_768,
    ML_KEM_1024,
    ML_DSA_44,
    ML_DSA_65,
    ML_DSA_87,
    SLH_DSA_SHA2_128s,
    HybridEd25519_ML_DSA_87,
    HybridX25519_ML_KEM_1024,
    Unknown             // Unknown or custom algorithm
};

// Quantum security levels
enum class QuantumSecurityLevel {
    Level1 = 1,      // 128-bit classical equivalent
    Level2 = 2,      // 192-bit classical equivalent
    Level3 = 3,      // 256-bit classical equivalent
    Level4 = 4,      // 256-bit quantum-resistant
    Level5 = 5       // 512-bit quantum-resistant (maximum)
};

// NSA classification levels
enum class NSAClassificationLevel {
    Unclassified,    // No NSA classification
    Confidential,     // NSA Confidential level
    Secret,          // NSA Secret level
    TopSecret,       // NSA Top Secret level
    TS_SCI           // NSA Top Secret/SCI (Special Compartmented Information)
};

// Quantum key types
enum class QuantumKeyType {
    IdentityKey,     // Identity key (EdDSA)
    PreKey,          // Signed pre-key (X25519)
    OneTimeKey,      // One-time pre-key (X25519)
    Encapsulation,   // Key encapsulation mechanism (KEM)
    Signature,       // Digital signature mechanism (DSM)
    Symmetric,       // Symmetric key (hybrid)
    Hybrid,          // Hybrid classical/quantum key
    Backup           // TPM-backed backup key
};

enum class SecurityEventType {
    Unknown,
    APT_Indicator,
    DeviceAttestation,
    QuantumIntrusion,
};

enum class SecurityEventSeverity {
    Low,
    Medium,
    High,
};

} // namespace Data
