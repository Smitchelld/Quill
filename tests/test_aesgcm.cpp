#include <gtest/gtest.h>
#include "crypto/AesGcm.h"

static Bytes key32() { return Bytes(32, 0x5a); }

TEST(AesGcm, StringRoundtrip) {
    auto enc = AesGcm::encrypt(key32(), std::string("tajna wiadomosc"));
    EXPECT_EQ(enc.nonce.size(), AesGcm::IV_LEN);
    EXPECT_EQ(AesGcm::decrypt(key32(), enc.nonce, enc.ciphertext), "tajna wiadomosc");
}

TEST(AesGcm, BytesRoundtrip) {
    Bytes plain(70000, 0xab); // > 64KB (rozmiar chunka transferu plikow)
    auto enc = AesGcm::encrypt(key32(), plain);
    EXPECT_EQ(AesGcm::decrypt_bytes(key32(), enc.nonce, enc.ciphertext), plain);
}

TEST(AesGcm, TamperedCiphertextRejected) {
    auto enc = AesGcm::encrypt(key32(), std::string("wiadomosc"));
    enc.ciphertext[0] ^= 0x01;
    EXPECT_THROW(AesGcm::decrypt(key32(), enc.nonce, enc.ciphertext),
                 std::runtime_error);
}

TEST(AesGcm, TamperedTagRejected) {
    auto enc = AesGcm::encrypt(key32(), std::string("wiadomosc"));
    enc.ciphertext.back() ^= 0x01; // tag = ostatnie 16B
    EXPECT_THROW(AesGcm::decrypt(key32(), enc.nonce, enc.ciphertext),
                 std::runtime_error);
}

TEST(AesGcm, WrongKeyRejected) {
    auto enc = AesGcm::encrypt(key32(), std::string("wiadomosc"));
    Bytes other(32, 0x5b);
    EXPECT_THROW(AesGcm::decrypt(other, enc.nonce, enc.ciphertext),
                 std::runtime_error);
}

TEST(AesGcm, NonceUniquePerEncryption) {
    auto a = AesGcm::encrypt(key32(), std::string("x"));
    auto b = AesGcm::encrypt(key32(), std::string("x"));
    EXPECT_NE(a.nonce, b.nonce); // nigdy nie reużywamy nonce
}

TEST(AesGcm, RejectsBadKeySize) {
    EXPECT_THROW(AesGcm::encrypt(Bytes(16, 0x00), std::string("x")),
                 std::invalid_argument);
}
