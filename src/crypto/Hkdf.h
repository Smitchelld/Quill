#ifndef QUILL_HKDF_H
#define QUILL_HKDF_H

#include <vector>
#include <string>
#include <cstdint>

using Bytes = std::vector<uint8_t>;

// ── HKDF-SHA256 (RFC 5869, OpenSSL EVP_KDF) ───────────────────────
// Wyprowadza klucz sesji z sekretu Kyber zamiast używać go bezpośrednio.
//
// Po co, skoro shared_secret z ML-KEM jest już jednorodnie losowy?
//  1. Wiązanie klucza z transkryptem handshake'u (salt = pub_key || ciphertext)
//     — klucz jest unikalny dla TEJ wymiany, nie tylko dla tego sekretu.
//  2. Separacja domen (info zawiera wersję protokołu i poziom bezpieczeństwa)
//     — ten sam sekret nigdy nie wyprowadzi tego samego klucza w innym kontekście.
//  3. Zgodność z praktyką (TLS 1.3, Signal): surowy output KEM nie jest
//     nigdy używany bezpośrednio jako klucz szyfrujący.
class Hkdf {
public:
    static constexpr size_t SESSION_KEY_LEN = 32; // AES-256

    // HKDF-Extract + HKDF-Expand (SHA-256).
    // ikm  — input keying material (shared_secret z Kyber)
    // salt — transkrypt handshake'u (kyber_pub || kem_ciphertext)
    // info — etykieta separacji domen, np. "quill-session-v1|BALANCED"
    // Rzuca std::runtime_error przy błędzie OpenSSL lub pustym IKM.
    static Bytes derive(const Bytes& ikm,
                        const Bytes& salt,
                        const std::string& info,
                        size_t out_len = SESSION_KEY_LEN);

    // Buduje etykietę info dla klucza sesji danego poziomu bezpieczeństwa.
    static std::string session_info(const std::string& level);
};

#endif // QUILL_HKDF_H
