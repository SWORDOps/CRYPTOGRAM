project(UnitTests)

find_package(Catch2 REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(test_cryptogram_features
    test_cryptogram_features.cpp
)

target_link_libraries(test_cryptogram_features
    PRIVATE
    Catch2::Catch2WithMain
    desktop-app::lib_base
    desktop-app::lib_crl
    desktop-app::lib_ui
    # Add other necessary libraries
)

add_executable(test_double_ratchet
    test_double_ratchet.cpp
)

target_link_libraries(test_double_ratchet
    PRIVATE
    Catch2::Catch2WithMain
    desktop-app::lib_base
    desktop-app::lib_ui
    OpenSSL::Crypto
)

add_executable(test_mls_protocol
    test_mls_protocol.cpp
)

target_link_libraries(test_mls_protocol
    PRIVATE
    Catch2::Catch2WithMain
    desktop-app::lib_base
    desktop-app::lib_crl
)

# ─── E2E Test Targets ───────────────────────────────────────────────────────────

add_executable(test_e2e_crypto_primitives
    test_e2e_crypto_primitives.cpp
)

target_link_libraries(test_e2e_crypto_primitives
    PRIVATE
    Catch2::Catch2WithMain
    OpenSSL::Crypto
)

add_executable(test_e2e_signal_protocol
    test_e2e_signal_protocol.cpp
)

target_link_libraries(test_e2e_signal_protocol
    PRIVATE
    Catch2::Catch2WithMain
    OpenSSL::Crypto
)

add_executable(test_e2e_mls_protocol
    test_e2e_mls_protocol.cpp
)

target_link_libraries(test_e2e_mls_protocol
    PRIVATE
    Catch2::Catch2WithMain
    OpenSSL::Crypto
)

add_executable(test_e2e_build_verification
    test_e2e_build_verification.cpp
)

target_link_libraries(test_e2e_build_verification
    PRIVATE
    Catch2::Catch2WithMain
)

add_executable(test_e2e_android_jni
    test_e2e_android_jni.cpp
)

target_link_libraries(test_e2e_android_jni
    PRIVATE
    Catch2::Catch2WithMain
)

add_executable(test_e2e_counterintelligence
    test_e2e_counterintelligence.cpp
)

target_link_libraries(test_e2e_counterintelligence
    PRIVATE
    Catch2::Catch2WithMain
)

add_executable(test_e2e_roundtrip
    test_e2e_roundtrip.cpp
)

target_link_libraries(test_e2e_roundtrip
    PRIVATE
    Catch2::Catch2WithMain
    OpenSSL::Crypto
)

# Cross-side conformance for the FIXED X3DH/double-ratchet spec
# (desktop data_signal_protocol.cpp identity-leg fix). Pure OpenSSL.
add_executable(test_e2e_x3dh_fixed
    test_e2e_x3dh_fixed.cpp
)

target_link_libraries(test_e2e_x3dh_fixed
    PRIVATE
    Catch2::Catch2WithMain
    OpenSSL::Crypto
)

# Path 2 host test: Android identity + session persistence in the JNI-free
# InteropCore. Standalone main(); needs only OpenSSL — no Catch2, no Qt.
add_executable(test_android_persistence_host
    test_android_persistence_host.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../../telegram-android/TMessagesProj/jni/cryptogram/interop/InteropCore.cpp
)

target_include_directories(test_android_persistence_host
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../telegram-android/TMessagesProj/jni/cryptogram
)

target_link_libraries(test_android_persistence_host
    PRIVATE
    OpenSSL::Crypto
)

# Covert-channel CNSA 2.0 alignment (data_covert_channel.cpp): level-gated
# uniform SHA-384 chain (HKDF-SHA384, 48-byte key, HMAC-SHA-384, 128-byte
# block) vs the legacy uniform SHA-256 chain. Pure OpenSSL.
add_executable(test_covert_channel_sha384
    test_covert_channel_sha384.cpp
)

target_link_libraries(test_covert_channel_sha384
    PRIVATE
    Catch2::Catch2WithMain
    OpenSSL::Crypto
)

# Exercises the production QuantumGuard implementation itself (ML-KEM
# encapsulation/decapsulation, AES-256-GCM, key import and persistence).
# Requires Qt6::Core, so it is NOT part of the minimal standalone CI set.
find_package(Qt6 COMPONENTS Core QUIET)
if (Qt6_FOUND)
    add_executable(test_e2e_quantum_kem
        test_e2e_quantum_kem.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../Telegram/SourceFiles/data/data_quantumguard.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../Telegram/lib_base/base/random.cpp
    )

    target_include_directories(test_e2e_quantum_kem
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../../Telegram/SourceFiles
        ${CMAKE_CURRENT_SOURCE_DIR}/../../Telegram/lib_base
        ${CMAKE_CURRENT_SOURCE_DIR}/../../Telegram/ThirdParty/GSL/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../../Telegram/ThirdParty/expected/include
    )

    target_link_libraries(test_e2e_quantum_kem
        PRIVATE
        Catch2::Catch2WithMain
        OpenSSL::Crypto
        Qt6::Core
    )
    # Exercises the production EnhancedPrivacyCrypto unit itself (PBKDF2
    # key derivation, salted AES-256-GCM envelopes, legacy compatibility).
    # Requires Qt6::Core, so it is NOT part of the minimal standalone CI set.
    add_executable(test_e2e_enhanced_privacy
        test_e2e_enhanced_privacy.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../Telegram/SourceFiles/data/enhanced_privacy_crypto.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../Telegram/lib_base/base/random.cpp
    )

    target_include_directories(test_e2e_enhanced_privacy
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../../Telegram/SourceFiles
        ${CMAKE_CURRENT_SOURCE_DIR}/../../Telegram/lib_base
        ${CMAKE_CURRENT_SOURCE_DIR}/../../Telegram/ThirdParty/GSL/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../../Telegram/ThirdParty/expected/include
    )

    target_link_libraries(test_e2e_enhanced_privacy
        PRIVATE
        Catch2::Catch2WithMain
        OpenSSL::Crypto
        Qt6::Core
    )
endif()
