#include "AesGcm.h"
#include <openssl/rand.h>
#include <stdexcept>
#include <memory>

// ── WERSJE DLA TEKSTU (Czat) ─────────────────────────────────────────────────

EncryptedData AesGcm::encrypt(const Bytes& key, const std::string& plaintext) {
    if (key.size() != 32) throw std::invalid_argument("AES-256 wymaga klucza 32-bajtowego");

    EncryptedData result;
    result.nonce.resize(IV_LEN);
    RAND_bytes(result.nonce.data(), IV_LEN);

    auto ctx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>(
        EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);

    EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr);
    EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), result.nonce.data());

    Bytes temp_ct(plaintext.size());
    int len = 0, total_len = 0;

    EVP_EncryptUpdate(ctx.get(), temp_ct.data(), &len,
                      reinterpret_cast<const uint8_t*>(plaintext.data()), (int)plaintext.size());
    total_len = len;

    EVP_EncryptFinal_ex(ctx.get(), temp_ct.data() + len, &len);
    total_len += len;

    Bytes tag(TAG_LEN);
    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag.data());

    result.ciphertext = std::move(temp_ct);
    result.ciphertext.insert(result.ciphertext.end(), tag.begin(), tag.end());

    return result;
}

std::string AesGcm::decrypt(const Bytes& key, const Bytes& nonce, const Bytes& ciphertext) {
    if (key.size() != 32) throw std::invalid_argument("Błędny rozmiar klucza AES");
    if (nonce.size() != IV_LEN) throw std::invalid_argument("Błędny rozmiar Nonce (wymagane 12B)");
    if (ciphertext.size() < TAG_LEN) throw std::runtime_error("Dane zaszyfrowane są za krótkie (brak TAGa)");

    int ct_len = (int)ciphertext.size() - TAG_LEN;
    const uint8_t* tag_ptr = ciphertext.data() + ct_len;

    auto ctx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>(
        EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);

    EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr);
    EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data());

    Bytes plaintext(ct_len);
    int len = 0;

    EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len, ciphertext.data(), ct_len);

    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void*)tag_ptr);

    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &len) <= 0) {
        throw std::runtime_error("INTEGRALITY ERROR. Message tampered!");
    }

    return {plaintext.begin(), plaintext.end()};
}


// ── WERSJE DLA BAJTÓW BINARNYCH (Transfer Plików) ────────────────────────────

EncryptedData AesGcm::encrypt(const Bytes& key, const Bytes& plaintext_bytes) {
    if (key.size() != 32) throw std::invalid_argument("AES-256 wymaga klucza 32-bajtowego");

    EncryptedData result;
    result.nonce.resize(IV_LEN);
    RAND_bytes(result.nonce.data(), IV_LEN);

    auto ctx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>(
        EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);

    EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr);
    EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), result.nonce.data());

    Bytes temp_ct(plaintext_bytes.size());
    int len = 0, total_len = 0;

    // Zamiast reinterpret_cast używamy bezpośrednio danych wektora (są to uint8_t)
    EVP_EncryptUpdate(ctx.get(), temp_ct.data(), &len,
                      plaintext_bytes.data(), (int)plaintext_bytes.size());
    total_len = len;

    EVP_EncryptFinal_ex(ctx.get(), temp_ct.data() + len, &len);
    total_len += len;

    Bytes tag(TAG_LEN);
    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag.data());

    result.ciphertext = std::move(temp_ct);
    result.ciphertext.insert(result.ciphertext.end(), tag.begin(), tag.end());

    return result;
}

Bytes AesGcm::decrypt_bytes(const Bytes& key, const Bytes& nonce, const Bytes& ciphertext) {
    if (key.size() != 32) throw std::invalid_argument("Błędny rozmiar klucza AES");
    if (nonce.size() != IV_LEN) throw std::invalid_argument("Błędny rozmiar Nonce (wymagane 12B)");
    if (ciphertext.size() < TAG_LEN) throw std::runtime_error("Dane zaszyfrowane są za krótkie (brak TAGa)");

    int ct_len = (int)ciphertext.size() - TAG_LEN;
    const uint8_t* tag_ptr = ciphertext.data() + ct_len;

    auto ctx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>(
        EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);

    EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr);
    EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data());

    Bytes plaintext(ct_len);
    int len = 0;

    EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len, ciphertext.data(), ct_len);
    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void*)tag_ptr);

    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &len) <= 0) {
        throw std::runtime_error("INTEGRITY ERROR: plik naruszony lub błędny klucz!");
    }

    return plaintext;
}