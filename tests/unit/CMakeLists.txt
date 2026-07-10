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
