#include <gtest/gtest.h>
#include "crypto/DilithiumSign.h"

class DsaLevels : public ::testing::TestWithParam<const char*> {};

TEST_P(DsaLevels, SignVerifyRoundtrip) {
    DilithiumSign signer(GetParam());
    auto kp = signer.generate_keypair();
    Bytes msg = {'q', 'u', 'i', 'l', 'l'};
    auto sig = signer.sign(msg, kp.secret_key);
    EXPECT_TRUE(signer.verify(msg, sig, kp.public_key));
}

TEST_P(DsaLevels, TamperedMessageFailsVerification) {
    DilithiumSign signer(GetParam());
    auto kp  = signer.generate_keypair();
    Bytes msg = {'q', 'u', 'i', 'l', 'l'};
    auto sig = signer.sign(msg, kp.secret_key);
    msg[0] ^= 1;
    EXPECT_FALSE(signer.verify(msg, sig, kp.public_key));
}

TEST_P(DsaLevels, TamperedSignatureFailsVerification) {
    DilithiumSign signer(GetParam());
    auto kp  = signer.generate_keypair();
    Bytes msg = {'q', 'u', 'i', 'l', 'l'};
    auto sig = signer.sign(msg, kp.secret_key);
    sig[0] ^= 1;
    EXPECT_FALSE(signer.verify(msg, sig, kp.public_key));
}

TEST_P(DsaLevels, WrongPublicKeyFailsVerification) {
    DilithiumSign signer(GetParam());
    auto kp1 = signer.generate_keypair();
    auto kp2 = signer.generate_keypair();
    Bytes msg = {'q', 'u', 'i', 'l', 'l'};
    auto sig = signer.sign(msg, kp1.secret_key);
    EXPECT_FALSE(signer.verify(msg, sig, kp2.public_key));
}

INSTANTIATE_TEST_SUITE_P(AllLevels, DsaLevels,
                         ::testing::Values("FAST", "BALANCED", "MAX"));

TEST(Dilithium, LevelAlgorithmMapping) {
    EXPECT_STREQ(DilithiumSign("FAST").algo_name(),     "Falcon-512");
    EXPECT_STREQ(DilithiumSign("BALANCED").algo_name(), "ML-DSA-65");
    EXPECT_STREQ(DilithiumSign("MAX").algo_name(),      "ML-DSA-87");
    EXPECT_THROW(DilithiumSign("ULTRA"), std::runtime_error);
}
