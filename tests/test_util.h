#ifndef QUILL_TEST_UTIL_H
#define QUILL_TEST_UTIL_H

#include <filesystem>
#include <random>
#include <string>
#include <cstdlib>
#include <vector>
#include <cstdint>

using Bytes = std::vector<uint8_t>;

// Katalog tymczasowy per test — RAII, sprzątany w destruktorze
class TempDir {
public:
    explicit TempDir(const std::string& prefix) {
        std::random_device rd;
        m_path = std::filesystem::temp_directory_path() /
                 (prefix + "_" + std::to_string(rd()));
        std::filesystem::create_directories(m_path);
    }
    ~TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(m_path, ec);
    }
    const std::filesystem::path& path() const { return m_path; }

private:
    std::filesystem::path m_path;
};

inline std::string hex(const Bytes& b) {
    static const char* H = "0123456789abcdef";
    std::string s;
    for (uint8_t x : b) { s += H[x >> 4]; s += H[x & 0xF]; }
    return s;
}

#endif // QUILL_TEST_UTIL_H
