cmake_minimum_required(VERSION 3.24)

project(jtk)

enable_testing()

find_package(OpenSSL REQUIRED)
find_package(GTest REQUIRED)

add_executable(jkt
    src/main.cpp
    src/safehandle.cpp
    src/jks.cpp
    src/jks_util.cpp
    src/pkcs12.cpp
    src/x509.cpp)

target_include_directories(jkt PUBLIC include/
    )

target_link_libraries(jkt PUBLIC
    )

target_link_directories(jkt PUBLIC
    ${PROJECT_SOURCE_DIR}/build/lib
    )

target_link_libraries(jkt PRIVATE OpenSSL::SSL)
target_link_libraries(jkt PRIVATE OpenSSL::Crypto)
set_property(TARGET jkt PROPERTY CXX_STANDARD 20)


add_executable(test-jkt
    src/safehandle.cpp
    src/jks_util.cpp
    src/x509.cpp
    src/jks.cpp
    src/pkcs12.cpp
    test/test_jks_util.cpp
    test/test_jks_cert_data.cpp
    test/test_pkcs12.cpp)
target_include_directories(test-jkt PUBLIC include/
    )
target_link_libraries(test-jkt PRIVATE GTest::gtest GTest::gtest_main)
target_link_libraries(test-jkt PRIVATE OpenSSL::SSL)
target_link_libraries(test-jkt PRIVATE OpenSSL::Crypto)

set_property(TARGET test-jkt PROPERTY CXX_STANDARD 20)

add_test(AllTests test-jkt)

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/test/files DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/test/)

