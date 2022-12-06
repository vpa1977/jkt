cmake_minimum_required(VERSION 3.24)

project(jtk)

#add_subdirectory(poco)
find_package(OpenSSL REQUIRED)

add_executable(jkt
    src/main.cpp
    src/container.cpp)
message(Poco::Crypto)
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

