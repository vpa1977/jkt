cmake_minimum_required(VERSION 3.24)

project(jtk)

enable_testing()

find_package(OpenSSL REQUIRED)
find_package(GTest REQUIRED)

add_executable(jkt
    src/main.cpp
    src/safehandle.cpp
    src/jks.cpp
    src/util.cpp)

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
    src/util.cpp
    test/test_util.cpp)
target_include_directories(test-jkt PUBLIC include/
    )
target_link_libraries(test-jkt GTest::gtest GTest::gtest_main)
set_property(TARGET test-jkt PROPERTY CXX_STANDARD 20)

add_test(AllTests test-jkt)


