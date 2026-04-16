//
// Created by mitchellds on 16.04.2026.
//

#ifndef QUILL_CRYPTO_H
#define QUILL_CRYPTO_H

#include <openssl/rand.h>
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <vector>
#include <string>
#include <stdexcept>
#include <cstring>

using Bytes = std::vector<uint8_t>;

// ── Kyber-768 KEM ──────────────────────────────────────────────
struct KyberKeyPair {
    Bytes pub;   // public key
    Bytes priv;  // private key
};

inline KyberKeyPair kyber_keygen() {
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (!kem) throw std::runtime_error("Kyber init failed");

    KyberKeyPair kp;
    kp.pub.resize(kem->length_public_key);
    kp.priv.resize(kem->length_secret_key);

    OQS_KEM_keypair(kem, kp.pub.data(), kp.priv.data());
    OQS_KEM_free(kem);
    return kp;
}

// return {ciphertext, shared_secret}
inline std::pair<Bytes, Bytes> kyber_encaps(const Bytes& pub) {
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    Bytes ct(kem->length_ciphertext);
    Bytes ss(kem->length_shared_secret);
    OQS_KEM_encaps(kem, ct.data(), ss.data(), pub.data());
    OQS_KEM_free(kem);
    return {ct, ss};
}

inline Bytes kyber_decaps(const Bytes& ct, const Bytes& priv) {
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    Bytes ss(kem->length_shared_secret);
    OQS_KEM_decaps(kem, ss.data(), ct.data(), priv.data());
    OQS_KEM_free(kem);
    return ss;
}

// ── AES-256-GCM ────────────────────────────────────────────────

inline Bytes aes_encrypt(const Bytes& key, const std::string& plaintext) {
    Bytes nonce(12);
    if (!RAND_bytes(nonce.data(), nonce.size()))
        throw std::runtime_error("RAND_bytes failed");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("CTX alloc failed");

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr))
        throw std::runtime_error("EncryptInit failed");

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr))
        throw std::runtime_error("IVLEN failed");

    if (!EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()))
        throw std::runtime_error("Key init failed");

    Bytes ciphertext(plaintext.size());
    int len = 0;
    int total = 0;

    if (!EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
        reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size()))
        throw std::runtime_error("EncryptUpdate failed");

    total = len;

    if (!EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len))
        throw std::runtime_error("EncryptFinal failed");

    total += len;

    Bytes tag(16);
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()))
        throw std::runtime_error("Get tag failed");

    EVP_CIPHER_CTX_free(ctx);

    // result: nonce + ciphertext + tag
    Bytes result;
    result.reserve(12 + total + 16);

    result.insert(result.end(), nonce.begin(), nonce.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.begin() + total);
    result.insert(result.end(), tag.begin(), tag.end());

    return result;
}

inline std::string aes_decrypt(const Bytes& key, const Bytes& data) {
    if (data.size() < 12 + 16)
        throw std::runtime_error("Message to short");

    const uint8_t* nonce = data.data();
    const uint8_t* ct    = data.data() + 12;
    int ct_len           = data.size() - 12 - 16;
    const uint8_t* tag   = data.data() + data.size() - 16;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("CTX alloc failed");

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr))
        throw std::runtime_error("DecryptInit failed");

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr))
        throw std::runtime_error("IVLEN failed");

    if (!EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce))
        throw std::runtime_error("Key init failed");

    Bytes plain(ct_len);
    int len = 0;
    int total = 0;

    if (!EVP_DecryptUpdate(ctx, plain.data(), &len, ct, ct_len))
        throw std::runtime_error("DecryptUpdate failed");

    total = len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag))
        throw std::runtime_error("Set tag failed");

    int ret = EVP_DecryptFinal_ex(ctx, plain.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0)
        throw std::runtime_error("AES-GCM auth failed — message manipulated!");

    total += len;

    return {plain.begin(), plain.begin() + total};
}


#endif //QUILL_CRYPTO_H
