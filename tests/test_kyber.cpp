#include <gtest/gtest.h>
#include "crypto/KyberKEM.h"

class KyberLevels : public ::testing::TestWithParam<const char*> {};

TEST_P(KyberLevels, EncapsDecapsSharedSecretMatches) {
    KyberKEM kem(GetParam());
    auto kp = kem.generate_keypair();
    auto [ct, ss_client] = kem.encapsulate(kp.public_key);
    auto ss_server = kem.decapsulate(ct, kp.secret_key);
    EXPECT_EQ(ss_client, ss_server);
    EXPECT_GE(ss_client.size(), 32u);
}

TEST_P(KyberLevels, FreshKeypairsPerCall) {
    KyberKEM kem(GetParam());
    // PFS: kazdy handshake = nowa para Kyber
    EXPECT_NE(kem.generate_keypair().public_key,
              kem.generate_keypair().public_key);
}

TEST_P(KyberLevels, WrongSecretKeyGivesDifferentSecret) {
    KyberKEM kem(GetParam());
    auto kp1 = kem.generate_keypair();
    auto kp2 = kem.generate_keypair();
    auto [ct, ss] = kem.encapsulate(kp1.public_key);
    // ML-KEM: implicit rejection — dekapsulacja złym kluczem daje INNY sekret
    EXPECT_NE(kem.decapsulate(ct, kp2.secret_key), ss);
}

INSTANTIATE_TEST_SUITE_P(AllLevels, KyberLevels,
                         ::testing::Values("FAST", "BALANCED", "MAX"));

TEST(Kyber, UnknownLevelThrows) {
    EXPECT_THROW(KyberKEM("ULTRA"), std::runtime_error);
}
