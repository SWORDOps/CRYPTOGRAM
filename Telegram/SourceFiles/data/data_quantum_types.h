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
    ML_KEM_512,      // NIST ML-KEM-512 (Kyber-512)
    ML_KEM_768,      // NIST ML-KEM-768 (Kyber-768)
    ML_KEM_1024,     // NIST ML-KEM-1024 (Kyber-1024)
    ML_DSA_44,       // NIST ML-DSA-44 (Dilithium-2)
    ML_DSA_65,       // NIST ML-DSA-65 (Dilithium-3)
    ML_DSA_87,       // NIST ML-DSA-87 (Dilithium-5)
    SLH_DSA_SHA2_128s,  // NIST SLH-DSA-SHA2-128s (SPHINCS+-SHA2-128s)
    Unknown          // Unknown or custom algorithm
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
    Encapsulation,   // Key encapsulation mechanism (KEM)
    Signature,       // Digital signature mechanism (DSM)
    Symmetric,       // Symmetric key (for hybrid schemes)
    Hybrid           // Hybrid classical/quantum key
};

} // namespace Data
