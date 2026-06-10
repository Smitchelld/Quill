#include "Argon2.h"

#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <memory>
#include <stdexcept>

Bytes Argon2::random_salt() {
    Bytes salt(SALT_LEN);
    if (RAND_bytes(salt.data(), static_cast<int>(salt.size())) != 1)
        throw std::runtime_error("Argon2: RAND_bytes nie powiodl sie");
    return salt;
}

Bytes Argon2::derive(const std::string& passphrase,
                     const Bytes& salt,
                     uint32_t t_cost,
                     uint32_t m_cost_kib,
                     uint32_t lanes,
                     size_t out_len) {
    if (salt.empty())
        throw std::runtime_error("Argon2: pusta sol");

    using KdfPtr = std::unique_ptr<EVP_KDF, decltype(&EVP_KDF_free)>;
    using CtxPtr = std::unique_ptr<EVP_KDF_CTX, decltype(&EVP_KDF_CTX_free)>;

    KdfPtr kdf(EVP_KDF_fetch(nullptr, "ARGON2ID", nullptr), EVP_KDF_free);
    if (!kdf)
        throw std::runtime_error(
            "Argon2: ARGON2ID niedostepny w tej wersji OpenSSL (wymagane >= 3.2)");

    CtxPtr ctx(EVP_KDF_CTX_new(kdf.get()), EVP_KDF_CTX_free);
    if (!ctx)
        throw std::runtime_error("Argon2: EVP_KDF_CTX_new nie powiodl sie");

    uint32_t threads = 1; // lanes=1 nie wymaga OSSL_set_max_threads
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_PASSWORD,
            const_cast<char*>(passphrase.data()), passphrase.size()),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT,
            const_cast<uint8_t*>(salt.data()), salt.size()),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER,           &t_cost),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &m_cost_kib),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES,   &lanes),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS,        &threads),
        OSSL_PARAM_construct_end()
    };

    Bytes out(out_len);
    if (EVP_KDF_derive(ctx.get(), out.data(), out.size(), params) <= 0)
        throw std::runtime_error("Argon2: EVP_KDF_derive nie powiodl sie");

    return out;
}
