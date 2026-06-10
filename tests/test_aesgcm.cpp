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

// ── AAD (context binding / anty-replay) ──────────────────────────────────────

static Bytes aad_of(const std::string& s) { return Bytes(s.begin(), s.end()); }

TEST(AesGcm, AadRoundtrip) {
    Bytes aad = aad_of("CHAT|1");
    auto enc = AesGcm::encrypt(key32(), std::string("hej"), aad);
    EXPECT_EQ(AesGcm::decrypt(key32(), enc.nonce, enc.ciphertext, aad), "hej");
}

TEST(AesGcm, WrongAadRejected) {
    // Podmiana AAD (np. numeru sekwencji) musi unieważnić tag GCM.
    auto enc = AesGcm::encrypt(key32(), std::string("hej"), aad_of("CHAT|1"));
    EXPECT_THROW(AesGcm::decrypt(key32(), enc.nonce, enc.ciphertext, aad_of("CHAT|2")),
                 std::runtime_error);
}

TEST(AesGcm, MissingAadRejected) {
    // Atak: usunięcie AAD przy zachowaniu szyfrogramu nie może się udać.
    auto enc = AesGcm::encrypt(key32(), std::string("hej"), aad_of("CHAT|1"));
    EXPECT_THROW(AesGcm::decrypt(key32(), enc.nonce, enc.ciphertext),
                 std::runtime_error);
}

TEST(AesGcm, UnexpectedAadRejected) {
    // Odwrotnie: szyfrogram bez AAD nie może być przyjęty z AAD.
    auto enc = AesGcm::encrypt(key32(), std::string("hej"));
    EXPECT_THROW(AesGcm::decrypt(key32(), enc.nonce, enc.ciphertext, aad_of("CHAT|1")),
                 std::runtime_error);
}

TEST(AesGcm, AadBytesRoundtrip) {
    Bytes aad = aad_of("FILE|tid|7");
    Bytes plain(1000, 0x33);
    auto enc = AesGcm::encrypt(key32(), plain, aad);
    EXPECT_EQ(AesGcm::decrypt_bytes(key32(), enc.nonce, enc.ciphertext, aad), plain);
    EXPECT_THROW(AesGcm::decrypt_bytes(key32(), enc.nonce, enc.ciphertext, aad_of("FILE|tid|8")),
                 std::runtime_error);
}

// Symulacja powtórki na poziomie kryptograficznym: przechwycony pakiet (nonce+ct)
// z AAD="CHAT|5" deszyfruje się tylko z tym samym seq. Logika seq>last (fail-closed)
// w ChatApp odrzuca powtórzony seq; tu pokazujemy wiązanie kontekstu.
TEST(AesGcm, ReplayBoundToSeqViaAad) {
    auto enc = AesGcm::encrypt(key32(), std::string("transfer 100 PLN"), aad_of("CHAT|5"));
    // odbiorca, który spodziewa się następnego seq=6, użyje innego AAD -> odrzuci
    EXPECT_THROW(AesGcm::decrypt(key32(), enc.nonce, enc.ciphertext, aad_of("CHAT|6")),
                 std::runtime_error);
    // a oryginalny seq nadal działa (to właśnie wykrywa licznik seq<=last)
    EXPECT_EQ(AesGcm::decrypt(key32(), enc.nonce, enc.ciphertext, aad_of("CHAT|5")),
              "transfer 100 PLN");
}
