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
endif()
