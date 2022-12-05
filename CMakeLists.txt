cmake_minimum_required(VERSION 3.24)

project(jtk)

add_subdirectory(poco)

add_executable(jkt
    src/main.cpp
    src/container.cpp)
message(Poco::Crypto)
target_include_directories(jkt PUBLIC include/
    poco/Crypto/include
    poco/Foundation/include
    )

target_link_libraries(jkt PUBLIC
    PocoCryptod
    PocoFoundationd
    )

target_link_directories(jkt PUBLIC
    ${PROJECT_SOURCE_DIR}/build/lib
    )
