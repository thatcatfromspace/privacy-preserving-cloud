cmake_minimum_required(VERSION 3.14)
project(DataPrivateCloudSecurity CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)
include_directories(.)

find_package(OpenSSL REQUIRED)

# Crypto Library
add_library(crypto_core
    src/crypto/RSAGroupSig.cpp
    src/crypto/Utils.cpp
)
target_link_libraries(crypto_core OpenSSL::SSL OpenSSL::Crypto)

# Revocation Manager Servce
add_executable(rm_service
    src/rm/main.cpp
)
target_link_libraries(rm_service crypto_core OpenSSL::SSL OpenSSL::Crypto pthread)

# Cloud Service Provider Service
add_executable(csp_service
    src/csp/main.cpp
)
target_link_libraries(csp_service crypto_core OpenSSL::SSL OpenSSL::Crypto pthread)

# Tests
add_executable(test_crypto
    tests/test_crypto.cpp
)
target_link_libraries(test_crypto crypto_core OpenSSL::SSL OpenSSL::Crypto)
