cmake_minimum_required(VERSION 3.24)

project(jtk)

add_executable(jkt src/main.cpp)

target_include_directories(jkt PUBLIC include/)