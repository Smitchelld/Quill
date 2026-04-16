cmake_minimum_required(VERSION 3.20)
project(Quill)
set(CMAKE_CXX_STANDARD 23)

find_package(OpenSSL REQUIRED)
find_library(OQS_LIB oqs REQUIRED)
find_path(OQS_INCLUDE oqs/oqs.h REQUIRED)

add_executable(Quill main.cpp
        src/network.h)
target_include_directories(Quill PRIVATE ${OQS_INCLUDE})
target_link_libraries(Quill PRIVATE ${OQS_LIB} OpenSSL::Crypto)