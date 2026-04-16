cmake_minimum_required(VERSION 3.20)
project(Quill)
set(CMAKE_CXX_STANDARD 23)

find_package(OpenSSL REQUIRED)
find_library(OQS_LIB oqs REQUIRED)
find_path(OQS_INCLUDE oqs/oqs.h REQUIRED)

add_executable(Quill main.cpp
        src/network/network.h
        src/crypto/KryberKEM.cpp
        src/crypto/KryberKEM.h
        src/crypto/DilithiumSign.cpp
        src/crypto/DilithiumSign.h
        src/crypto/AesGcm.cpp
        src/crypto/AesGcm.h
        src/crypto/CryptoManager.cpp
        src/crypto/CryptoManager.h
        src/network/Socket.cpp
        src/network/Socket.h
        src/network/NetworkServer.cpp
        src/network/NetworkServer.h
        src/network/NetworkClient.cpp
        src/network/NetworkClient.h
        src/protocol/MessageFormat.cpp
        src/protocol/MessageFormat.h)
target_include_directories(Quill PRIVATE ${OQS_INCLUDE})
target_link_libraries(Quill PRIVATE ${OQS_LIB} OpenSSL::Crypto)