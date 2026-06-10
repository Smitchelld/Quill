#include <gtest/gtest.h>
#include "crypto/Hkdf.h"
#include "test_util.h"

// RFC 5869, Appendix A — oficjalne wektory testowe HKDF-SHA256

TEST(Hkdf, Rfc5869TestCase1) {
    Bytes ikm(22, 0x0b);
    Bytes salt;
    for (uint8_t i = 0; i <= 0x0c; ++i) salt.push_back(i);
    std::string info;
    for (int i = 0xf0; i <= 0xf9; ++i) info += static_cast<char>(i);

    Bytes okm = Hkdf::derive(ikm, salt, info, 42);
    EXPECT_EQ(hex(okm),
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865");
}

TEST(Hkdf, Rfc5869TestCase3_EmptySaltAndInfo) {
    Bytes ikm(22, 0x0b);
    Bytes okm = Hkdf::derive(ikm, {}, "", 42);
    EXPECT_EQ(hex(okm),
        "8da4e775a563c18f715f802a063c5a31"
        "b8a11f5c5ee1879ec3454e5f3c738d2d"
        "9d201395faa4b61a96c8");
}

TEST(Hkdf, ClientServerSymmetry) {
    Bytes ss(32, 0xaa);
    Bytes transcript(1600, 0x42);
    Bytes k1 = Hkdf::derive(ss, transcript, Hkdf::session_info("BALANCED"));
    Bytes k2 = Hkdf::derive(ss, transcript, Hkdf::session_info("BALANCED"));
    EXPECT_EQ(k1, k2);
    EXPECT_EQ(k1.size(), Hkdf::SESSION_KEY_LEN);
}

TEST(Hkdf, DomainSeparationByLevel) {
    Bytes ss(32, 0xaa);
    Bytes transcript(100, 0x42);
    EXPECT_NE(Hkdf::derive(ss, transcript, Hkdf::session_info("BALANCED")),
              Hkdf::derive(ss, transcript, Hkdf::session_info("MAX")));
}

TEST(Hkdf, TranscriptBinding) {
    Bytes ss(32, 0xaa);
    Bytes t1(100, 0x42);
    Bytes t2 = t1;
    t2[0] ^= 1;
    EXPECT_NE(Hkdf::derive(ss, t1, Hkdf::session_info("BALANCED")),
              Hkdf::derive(ss, t2, Hkdf::session_info("BALANCED")));
}

TEST(Hkdf, RejectsEmptyIkm) {
    EXPECT_THROW(Hkdf::derive({}, {0x01}, "x"), std::runtime_error);
}
