#include <gtest/gtest.h>
#include "crypto/Argon2.h"

// Małe parametry kosztowe w testach (8 MiB) — testujemy poprawność,
// nie odporność; pełne parametry (64 MiB) używane są w produkcji
static constexpr uint32_t T = 3, M = 8 * 1024, L = 1;

TEST(Argon2, Deterministic) {
    Bytes salt(16, 0x01);
    EXPECT_EQ(Argon2::derive("haslo", salt, T, M, L),
              Argon2::derive("haslo", salt, T, M, L));
}

TEST(Argon2, DifferentPassphraseDifferentKey) {
    Bytes salt(16, 0x01);
    EXPECT_NE(Argon2::derive("haslo-a", salt, T, M, L),
              Argon2::derive("haslo-b", salt, T, M, L));
}

TEST(Argon2, DifferentSaltDifferentKey) {
    EXPECT_NE(Argon2::derive("haslo", Bytes(16, 0x01), T, M, L),
              Argon2::derive("haslo", Bytes(16, 0x02), T, M, L));
}

TEST(Argon2, OutputLength) {
    Bytes salt = Argon2::random_salt();
    EXPECT_EQ(salt.size(), Argon2::SALT_LEN);
    EXPECT_EQ(Argon2::derive("x", salt, T, M, L, 32).size(), 32u);
    EXPECT_EQ(Argon2::derive("x", salt, T, M, L, 64).size(), 64u);
}

TEST(Argon2, RandomSaltsDiffer) {
    EXPECT_NE(Argon2::random_salt(), Argon2::random_salt());
}

TEST(Argon2, RejectsEmptySalt) {
    EXPECT_THROW(Argon2::derive("x", {}, T, M, L), std::runtime_error);
}
