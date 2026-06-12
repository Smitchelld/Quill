#include "Hkdf.h"

#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <stdexcept>
#include <memory>

std::string Hkdf::session_info(const std::string& level) {
    return "quill-aes256gcm-session-v1|" + level;
}

Bytes Hkdf::derive(const Bytes& ikm,
                   const Bytes& salt,
                   const std::string& info,
                   size_t out_len) {
    if (ikm.empty())
        throw std::runtime_error("HKDF: pusty material klucza (IKM)");
    if (out_len == 0)
        throw std::runtime_error("HKDF: zerowa dlugosc klucza wyjsciowego");

    using KdfPtr = std::unique_ptr<EVP_KDF, decltype(&EVP_KDF_free)>;
    using CtxPtr = std::unique_ptr<EVP_KDF_CTX, decltype(&EVP_KDF_CTX_free)>;

    KdfPtr kdf(EVP_KDF_fetch(nullptr, "HKDF", nullptr), EVP_KDF_free);
    if (!kdf)
        throw std::runtime_error("HKDF: EVP_KDF_fetch nie powiodl sie");

    CtxPtr ctx(EVP_KDF_CTX_new(kdf.get()), EVP_KDF_CTX_free);
    if (!ctx)
        throw std::runtime_error("HKDF: EVP_KDF_CTX_new nie powiodl sie");

    OSSL_PARAM params[5];
    size_t p = 0;
    params[p++] = OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_DIGEST, const_cast<char*>("SHA256"), 0);
    params[p++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_KEY, const_cast<uint8_t*>(ikm.data()), ikm.size());
    if (!salt.empty()) {
        params[p++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT, const_cast<uint8_t*>(salt.data()), salt.size());
    }
    if (!info.empty()) {
        params[p++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_INFO, const_cast<char*>(info.data()), info.size());
    }
    params[p] = OSSL_PARAM_construct_end();

    Bytes out(out_len);
    if (EVP_KDF_derive(ctx.get(), out.data(), out.size(), params) <= 0)
        throw std::runtime_error("HKDF: EVP_KDF_derive nie powiodl sie");

    return out;
}
