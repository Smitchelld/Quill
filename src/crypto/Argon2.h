#ifndef QUILL_ARGON2_H
#define QUILL_ARGON2_H

#include <vector>
#include <string>
#include <cstdint>

using Bytes = std::vector<uint8_t>;

class Argon2 {
public:
    static constexpr uint32_t T_COST     = 3;
    static constexpr uint32_t M_COST_KIB = 64 * 1024;
    static constexpr uint32_t LANES      = 1;
    static constexpr size_t   SALT_LEN   = 16;

    static Bytes derive(const std::string& passphrase,
                        const Bytes& salt,
                        uint32_t t_cost,
                        uint32_t m_cost_kib,
                        uint32_t lanes,
                        size_t out_len = 32);

    static Bytes random_salt();
};

#endif // QUILL_ARGON2_H
