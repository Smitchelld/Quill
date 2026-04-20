#ifndef QUILL_CRYPTO_H
#define QUILL_CRYPTO_H

#include <openssl/rand.h>
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <vector>
#include <string>
#include <stdexcept>
#include <map>

using Bytes = std::vector<uint8_t>;

inline const char* get_kyber_algo(const std::string& level) {
    if (level == "FAST") return OQS_KEM_alg_kyber_512;
    if (level == "BALANCED") return OQS_KEM_alg_kyber_768;
    if (level == "MAX") return OQS_KEM_alg_kyber_1024;
    throw std::runtime_error("Unknown kyber algorithm: " + level);
}

struct KyberKeyPair {
    Bytes pub;
    Bytes priv;
};

inline KyberKeyPair kyber_keygen(const std::string& level) {
    OQS_KEM* kem = OQS_KEM_new(get_kyber_algo(level));
    if (!kem) throw std::runtime_error("Kyber init failed");
    KyberKeyPair kp;
    kp.pub.resize(kem->length_public_key);
    kp.priv.resize(kem->length_secret_key);
    OQS_KEM_keypair(kem, kp.pub.data(), kp.priv.data());
    OQS_KEM_free(kem);
    return kp;
}

inline std::pair<Bytes, Bytes> kyber_encaps(const std::string& level, const Bytes& pub) {
    OQS_KEM* kem = OQS_KEM_new(get_kyber_algo(level));
    Bytes ct(kem->length_ciphertext);
    Bytes ss(kem->length_shared_secret);
    OQS_KEM_encaps(kem, ct.data(), ss.data(), pub.data());
    OQS_KEM_free(kem);
    return {ct, ss};
}

inline Bytes kyber_decaps(const std::string& level, const Bytes& ct, const Bytes& priv) {
    OQS_KEM* kem = OQS_KEM_new(get_kyber_algo(level));
    Bytes ss(kem->length_shared_secret);
    OQS_KEM_decaps(kem, ss.data(), ct.data(), priv.data());
    OQS_KEM_free(kem);
    return ss;
}

// ── AES-256-GCM ────────────────────────────────────────────────
inline Bytes aes_encrypt(const Bytes& key, const std::string& plaintext) {
    Bytes nonce(12);
    RAND_bytes(nonce.data(), static_cast<int>(nonce.size()));
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data());
    Bytes ciphertext(plaintext.size());
    int len = 0, total = 0;
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const uint8_t*>(plaintext.data()), static_cast<int>(plaintext.size()));
    total = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    total += len;
    Bytes tag(16);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
    EVP_CIPHER_CTX_free(ctx);
    Bytes result;
    result.insert(result.end(), nonce.begin(), nonce.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.begin() + total);
    result.insert(result.end(), tag.begin(), tag.end());
    return result;
}

inline std::string aes_decrypt(const Bytes& key, const Bytes& data) {
    if (data.size() < 28) throw std::runtime_error("Message too short");
    const uint8_t *nonce = data.data(), *ct = data.data() + 12, *tag = data.data() + data.size() - 16;
    int ct_len = static_cast<int>(data.size()) - 28;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce);
    Bytes plain(ct_len);
    int len = 0;
    EVP_DecryptUpdate(ctx, plain.data(), &len, ct, ct_len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag);
    if (EVP_DecryptFinal_ex(ctx, plain.data() + len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-GCM auth failed — message manipulated!");
    }
    EVP_CIPHER_CTX_free(ctx);
    return {plain.begin(), plain.end()};
}

#endif