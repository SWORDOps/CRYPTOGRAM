project(UnitTests)

find_package(Catch2 REQUIRED)

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
