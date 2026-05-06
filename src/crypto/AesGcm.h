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

    static EncryptedData encrypt(const Bytes& key, const std::string& plaintext);

    static std::string decrypt(const Bytes& key, const Bytes& nonce, const Bytes& ciphertext);
};

#endif