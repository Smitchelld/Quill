cmake_minimum_required(VERSION 3.20)
project(Quill)
set(CMAKE_CXX_STANDARD 23)

# ── DEPENDENCIES ──────────────────────────────────────────────────
find_package(OpenSSL REQUIRED)
find_package(glfw3   REQUIRED)
find_package(OpenGL  REQUIRED)
find_package(nlohmann_json REQUIRED)
find_library(OQS_LIB oqs REQUIRED)
find_path(OQS_INCLUDE oqs/oqs.h REQUIRED)


# ── IMGUI (submoduł: third_party/imgui) ───────────────────────────
set(IMGUI_DIR ${CMAKE_SOURCE_DIR}/third_party/imgui)
add_library(imgui STATIC
        ${IMGUI_DIR}/imgui.cpp
        ${IMGUI_DIR}/imgui_draw.cpp
        ${IMGUI_DIR}/imgui_tables.cpp
        ${IMGUI_DIR}/imgui_widgets.cpp
        ${IMGUI_DIR}/backends/imgui_impl_glfw.cpp
        ${IMGUI_DIR}/backends/imgui_impl_opengl3.cpp
)
target_include_directories(imgui PUBLIC
        ${IMGUI_DIR}
        ${IMGUI_DIR}/backends
)
target_link_libraries(imgui PUBLIC glfw OpenGL::GL)

# ── GŁÓWNY BINARY ─────────────────────────────────────────────────
add_executable(Quill
        main.cpp
        src/network/network.h
        src/crypto/KyberKEM.cpp
        src/crypto/KyberKEM.h
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
        src/protocol/MessageFormat.h
        src/frontend/ChatApp.cpp
        src/frontend/ChatApp.h
        src/frontend/Theme.h

)

target_include_directories(Quill PRIVATE
        ${OQS_INCLUDE}
        ${IMGUI_DIR}
        ${IMGUI_DIR}/backends
)

target_link_libraries(Quill PRIVATE
        imgui
        ${OQS_LIB}
        OpenSSL::Crypto
        nlohmann_json::nlohmann_json
)