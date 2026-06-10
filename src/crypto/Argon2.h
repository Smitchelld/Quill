#ifndef QUILL_ARGON2_H
#define QUILL_ARGON2_H

#include <vector>
#include <string>
#include <cstdint>

using Bytes = std::vector<uint8_t>;

// ── Argon2id (RFC 9106, OpenSSL EVP_KDF) ──────────────────────────
// KDF do haseł: memory-hard, odporny na ataki GPU/ASIC.
// Używany WYŁĄCZNIE do szyfrowania kluczy tożsamości na dysku.
// (Klucze sesji wyprowadza Hkdf — inna funkcja, inny cel.)
class Argon2 {
public:
    // Parametry domyślne wg RFC 9106 (wariant "second recommended":
    // 64 MiB pamięci, 3 iteracje, 1 pas — bez wymogu wielowątkowości OpenSSL)
    static constexpr uint32_t T_COST     = 3;
    static constexpr uint32_t M_COST_KIB = 64 * 1024;
    static constexpr uint32_t LANES      = 1;
    static constexpr size_t   SALT_LEN   = 16;

    // Wyprowadza klucz z passphrase'a. Parametry kosztowe są jawne,
    // bo muszą być zapisane obok zaszyfrowanych danych (podnoszalność).
    // Rzuca std::runtime_error przy błędzie OpenSSL.
    static Bytes derive(const std::string& passphrase,
                        const Bytes& salt,
                        uint32_t t_cost,
                        uint32_t m_cost_kib,
                        uint32_t lanes,
                        size_t out_len = 32);

    // Losowa sól (RAND_bytes)
    static Bytes random_salt();
};

#endif // QUILL_ARGON2_H
