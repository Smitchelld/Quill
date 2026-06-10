#ifndef QUILL_AESGCM_H
#define QUILL_AESGCM_H

#include <vector>
#include <string>
#include <openssl/evp.h>

using Bytes = std::vector<uint8_t>;

struct EncryptedData {
    Bytes nonce;
    Bytes ciphertext;
};

class AesGcm {
public:
    static constexpr size_t IV_LEN = 12;
    static constexpr size_t TAG_LEN = 16;

    // AAD (Additional Authenticated Data) — uwierzytelniane, ale NIE szyfrowane.
    // Wiąże szyfrogram z kontekstem (np. numer sekwencji, typ wiadomości).
    // Ten sam AAD musi być podany przy deszyfrowaniu, inaczej tag GCM nie
    // przejdzie weryfikacji. Domyślnie pusty — zachowuje zgodność wsteczną.

    // Szyfrowanie ciągów znaków (np. czat)
    static EncryptedData encrypt(const Bytes& key, const std::string& plaintext,
                                 const Bytes& aad = {});

    // Szyfrowanie surowych bajtów (np. chunk pliku)
    static EncryptedData encrypt(const Bytes& key, const Bytes& plaintext_bytes,
                                 const Bytes& aad = {});

    // Deszyfrowanie do ciągu znaków
    static std::string decrypt(const Bytes& key, const Bytes& nonce,
                               const Bytes& ciphertext, const Bytes& aad = {});

    // Deszyfrowanie do surowych bajtów
    static Bytes decrypt_bytes(const Bytes& key, const Bytes& nonce,
                               const Bytes& ciphertext, const Bytes& aad = {});
};

#endif // QUILL_AESGCM_H