cmake_minimum_required(VERSION 3.20)
project(Quill)
set(CMAKE_CXX_STANDARD 23)

option(QUILL_BUILD_GUI "Build ImGui application (requires GLFW/OpenGL + imgui submodule)" ON)

# ── DEPENDENCIES ──────────────────────────────────────────────────
find_package(OpenSSL REQUIRED)
find_package(nlohmann_json REQUIRED)
find_library(OQS_LIB oqs REQUIRED)
find_path(OQS_INCLUDE oqs/oqs.h REQUIRED)

# Argon2id: OpenSSL >= 3.2 (EVP_KDF) albo libargon2 na starszych dystrybucjach (np. Ubuntu CI)
if (OPENSSL_VERSION VERSION_LESS "3.2")
    find_library(ARGON2_LIB argon2 REQUIRED)
    message(STATUS "OpenSSL ${OPENSSL_VERSION} — Argon2id przez libargon2")
else()
    message(STATUS "OpenSSL ${OPENSSL_VERSION} — Argon2id przez EVP_KDF")
endif()

if (QUILL_BUILD_GUI)
    find_package(glfw3  REQUIRED)
    find_package(OpenGL REQUIRED)

    # ── IMGUI (git submodule: third_party/imgui) ──────────────────
    set(IMGUI_DIR ${CMAKE_SOURCE_DIR}/third_party/imgui)
    if (NOT EXISTS "${IMGUI_DIR}/imgui.cpp")
        message(FATAL_ERROR
            "Missing Dear ImGui. Run: git submodule update --init --recursive")
    endif()
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
endif()

# ── QUILL CORE (krypto + sieć + protokół, bez UI — testowalne) ────
add_library(quill_core STATIC
        src/crypto/KyberKEM.cpp
        src/crypto/DilithiumSign.cpp
        src/crypto/AesGcm.cpp
        src/crypto/Hkdf.cpp
        src/crypto/Argon2.cpp
        src/crypto/IdentityManager.cpp
        src/crypto/ProfileManager.cpp
        src/crypto/TrustStore.cpp
        src/crypto/CryptoManager.cpp
        src/network/Socket.cpp
        src/network/NetworkServer.cpp
        src/network/NetworkClient.cpp
        src/protocol/MessageFormat.cpp
        src/protocol/FileTransfer.cpp
)
target_include_directories(quill_core PUBLIC
        ${OQS_INCLUDE}
        ${CMAKE_SOURCE_DIR}/src
)
target_link_libraries(quill_core PUBLIC
        ${OQS_LIB}
        OpenSSL::Crypto
        nlohmann_json::nlohmann_json
)
if (OPENSSL_VERSION VERSION_LESS "3.2")
    target_compile_definitions(quill_core PRIVATE QUILL_USE_LIBARGON2=1)
    target_link_libraries(quill_core PUBLIC ${ARGON2_LIB})
endif()

# ── GŁÓWNY BINARY ─────────────────────────────────────────────────
if (QUILL_BUILD_GUI)
    add_executable(Quill
            main.cpp
            src/frontend/ChatApp.cpp
            src/frontend/ChatAppRender.cpp
    )
    target_link_libraries(Quill PRIVATE quill_core imgui)
endif()

# ── TESTY (Google Test) ───────────────────────────────────────────
enable_testing()
find_package(GTest)
if (GTest_FOUND)
    add_executable(quill_tests
            tests/test_hkdf.cpp
            tests/test_argon2.cpp
            tests/test_aesgcm.cpp
            tests/test_kyber.cpp
            tests/test_dilithium.cpp
            tests/test_identity.cpp
            tests/test_profile.cpp
            tests/test_truststore.cpp
            tests/test_messageformat.cpp
            tests/test_filetransfer.cpp
            tests/test_cryptomanager.cpp
    )
    target_link_libraries(quill_tests PRIVATE quill_core GTest::gtest GTest::gtest_main)
    include(GoogleTest)
    gtest_discover_tests(quill_tests)
endif()
