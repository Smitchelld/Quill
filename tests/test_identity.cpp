#include <gtest/gtest.h>
#include "crypto/IdentityManager.h"
#include "test_util.h"

#include <fstream>
#include <sys/stat.h>

namespace fs = std::filesystem;

// Każdy test dostaje świeży katalog i czysty stan (activate czyści cache)
class IdentityTest : public ::testing::Test {
protected:
    void SetUp() override {
        m_tmp = std::make_unique<TempDir>("quill_id");
        IdentityManager::activate(m_tmp->path(), "");
    }
    void TearDown() override { IdentityManager::deactivate(); }

    fs::path key_path() const { return m_tmp->path() / "ML-DSA-65.id"; }

    static std::string magic_of(const fs::path& p) {
        std::ifstream f(p, std::ios::binary);
        char m[5] = {};
        f.read(m, 4);
        return m;
    }

    std::unique_ptr<TempDir> m_tmp;
};

TEST_F(IdentityTest, GeneratesAndPersistsPlaintext) {
    auto kp = IdentityManager::load_or_generate("BALANCED");
    EXPECT_FALSE(kp.public_key.empty());
    ASSERT_TRUE(fs::exists(key_path()));
    EXPECT_EQ(magic_of(key_path()), "QID1");

    struct stat st{};
    ::stat(key_path().c_str(), &st);
    EXPECT_EQ(st.st_mode & 0777, 0600u);
}

TEST_F(IdentityTest, ReloadGivesSameIdentity) {
    auto kp1 = IdentityManager::load_or_generate("BALANCED");
    IdentityManager::activate(m_tmp->path(), ""); // czyści cache => wymusza load
    auto kp2 = IdentityManager::load_or_generate("BALANCED");
    EXPECT_EQ(kp1.public_key, kp2.public_key);
}

TEST_F(IdentityTest, EncryptedSaveAndLoad) {
    IdentityManager::activate(m_tmp->path(), "tajne");
    auto kp1 = IdentityManager::load_or_generate("BALANCED");
    EXPECT_EQ(magic_of(key_path()), "QID2");

    IdentityManager::activate(m_tmp->path(), "tajne");
    auto kp2 = IdentityManager::load_or_generate("BALANCED");
    EXPECT_EQ(kp1.public_key, kp2.public_key);
}

TEST_F(IdentityTest, WrongPassphraseRejected) {
    IdentityManager::activate(m_tmp->path(), "dobre-haslo");
    IdentityManager::load_or_generate("BALANCED");

    IdentityManager::activate(m_tmp->path(), "zle-haslo");
    EXPECT_THROW(IdentityManager::load_or_generate("BALANCED"), std::runtime_error);
}

TEST_F(IdentityTest, EncryptedKeyWithoutPassphraseRejected) {
    IdentityManager::activate(m_tmp->path(), "haslo");
    IdentityManager::load_or_generate("BALANCED");

    IdentityManager::activate(m_tmp->path(), "");
    EXPECT_THROW(IdentityManager::load_or_generate("BALANCED"), std::runtime_error);
}

TEST_F(IdentityTest, Qid1ToQid2Migration) {
    auto kp1 = IdentityManager::load_or_generate("BALANCED"); // QID1
    ASSERT_EQ(magic_of(key_path()), "QID1");

    IdentityManager::activate(m_tmp->path(), "nowe-haslo");
    auto kp2 = IdentityManager::load_or_generate("BALANCED"); // migracja w miejscu
    EXPECT_EQ(magic_of(key_path()), "QID2");
    EXPECT_EQ(kp1.public_key, kp2.public_key); // tożsamość zachowana
}

TEST_F(IdentityTest, LoosePermissionsRejected) {
    IdentityManager::load_or_generate("BALANCED");
    ::chmod(key_path().c_str(), 0644);
    IdentityManager::activate(m_tmp->path(), "");
    EXPECT_THROW(IdentityManager::load_or_generate("BALANCED"), std::runtime_error);
}

TEST_F(IdentityTest, CorruptedKeyRejectedNotRegenerated) {
    IdentityManager::load_or_generate("BALANCED");
    {
        std::fstream f(key_path(), std::ios::in | std::ios::out | std::ios::binary);
        f.seekg(-1, std::ios::end);
        char c; f.get(c);
        f.seekp(-1, std::ios::end);
        f.put(static_cast<char>(c ^ 0xFF));
    }
    IdentityManager::activate(m_tmp->path(), "");
    // Uszkodzony klucz = wyjątek, NIE cicha regeneracja nowej tożsamości
    EXPECT_THROW(IdentityManager::load_or_generate("BALANCED"), std::runtime_error);
    EXPECT_TRUE(fs::exists(key_path()));
}

TEST_F(IdentityTest, PerAlgorithmIdentities) {
    auto kp_bal = IdentityManager::load_or_generate("BALANCED");
    auto kp_max = IdentityManager::load_or_generate("MAX");
    EXPECT_NE(kp_bal.public_key, kp_max.public_key);
    EXPECT_TRUE(fs::exists(m_tmp->path() / "ML-DSA-65.id"));
    EXPECT_TRUE(fs::exists(m_tmp->path() / "ML-DSA-87.id"));
}

TEST(IdentityFingerprint, FormatAndDeterminism) {
    Bytes key(1952, 0x11);
    std::string fp = IdentityManager::fingerprint(key);
    EXPECT_EQ(fp.size(), 29u); // 6 grup x 4 hex + 5 myslnikow
    EXPECT_EQ(std::count(fp.begin(), fp.end(), '-'), 5);
    EXPECT_EQ(fp, IdentityManager::fingerprint(key));

    Bytes other(1952, 0x22);
    EXPECT_NE(fp, IdentityManager::fingerprint(other));
}
