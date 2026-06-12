#ifndef QUILL_HKDF_H
#define QUILL_HKDF_H

#include <vector>
#include <string>
#include <cstdint>

using Bytes = std::vector<uint8_t>;

// Session key from Kyber shared secret via HKDF-SHA256 (not raw KEM output).
class Hkdf {
public:
    static constexpr size_t SESSION_KEY_LEN = 32;

    static Bytes derive(const Bytes& ikm,
                        const Bytes& salt,
                        const std::string& info,
                        size_t out_len = SESSION_KEY_LEN);

    static std::string session_info(const std::string& level);
};

#endif // QUILL_HKDF_H
