#include <gtest/gtest.h>
#include "crypto/TrustStore.h"
#include "crypto/IdentityManager.h"
#include "test_util.h"

#include <fstream>
#include <sys/stat.h>

namespace fs = std::filesystem;

class TrustTest : public ::testing::Test {
protected:
    void SetUp() override {
        m_tmp = std::make_unique<TempDir>("quill_trust");
        // known_hosts żyje obok katalogu identity (w katalogu profilu)
        IdentityManager::activate(m_tmp->path() / "identity", "");
        m_keyA = Bytes(1952, 0x11);
        m_keyB = Bytes(1952, 0x22);
    }
    void TearDown() override { IdentityManager::deactivate(); }

    std::unique_ptr<TempDir> m_tmp;
    Bytes m_keyA, m_keyB;
    const std::string m_peer = "srv:1.2.3.4:7777";
};

TEST_F(TrustTest, FirstContactIsUnverifiedAndStored) {
    auto d = TrustStore::check_and_remember(m_peer, m_keyA, "ML-DSA-65");
    EXPECT_EQ(d.state, TrustState::UNVERIFIED);
    ASSERT_TRUE(fs::exists(TrustStore::store_path()));

    struct stat st{};
    ::stat(TrustStore::store_path().c_str(), &st);
    EXPECT_EQ(st.st_mode & 0777, 0600u);
}

TEST_F(TrustTest, SecondContactSameKeyIsKnown) {
    TrustStore::check_and_remember(m_peer, m_keyA, "ML-DSA-65");
    auto d = TrustStore::check_and_remember(m_peer, m_keyA, "ML-DSA-65");
    EXPECT_EQ(d.state, TrustState::KNOWN);
}

TEST_F(TrustTest, MarkVerifiedPromotes) {
    TrustStore::check_and_remember(m_peer, m_keyA, "ML-DSA-65");
    TrustStore::mark_verified(m_peer);
    auto d = TrustStore::check_and_remember(m_peer, m_keyA, "ML-DSA-65");
    EXPECT_EQ(d.state, TrustState::VERIFIED);
}

TEST_F(TrustTest, KeyChangeIsMismatchAndPreservesEntry) {
    auto first = TrustStore::check_and_remember(m_peer, m_keyA, "ML-DSA-65");
    TrustStore::mark_verified(m_peer);

    // "Atak": inny klucz dla tego samego peer_id
    auto d = TrustStore::check_and_remember(m_peer, m_keyB, "ML-DSA-65");
    EXPECT_EQ(d.state, TrustState::MISMATCH);
    EXPECT_EQ(d.stored_fingerprint, first.fingerprint);

    // Stary wpis przetrwał próbę ataku nietknięty
    auto again = TrustStore::check_and_remember(m_peer, m_keyA, "ML-DSA-65");
    EXPECT_EQ(again.state, TrustState::VERIFIED);
}

TEST_F(TrustTest, RemoveAllowsFreshTofu) {
    TrustStore::check_and_remember(m_peer, m_keyA, "ML-DSA-65");
    TrustStore::remove(m_peer);
    auto d = TrustStore::check_and_remember(m_peer, m_keyB, "ML-DSA-65");
    EXPECT_EQ(d.state, TrustState::UNVERIFIED);
}

TEST_F(TrustTest, DistinctPeersPerHostPort) {
    TrustStore::check_and_remember("srv:1.2.3.4:7777", m_keyA, "ML-DSA-65");
    auto d = TrustStore::check_and_remember("srv:1.2.3.4:8888", m_keyA, "ML-DSA-65");
    EXPECT_EQ(d.state, TrustState::UNVERIFIED);
    EXPECT_EQ(TrustStore::list().size(), 2u);
}

TEST_F(TrustTest, CorruptedKnownHostsIsHardError) {
    TrustStore::check_and_remember(m_peer, m_keyA, "ML-DSA-65");
    {
        std::ofstream f(TrustStore::store_path(), std::ios::trunc);
        f << "{zepsute";
    }
    // Zniszczona baza zaufania = incydent, nie cicha reinicjalizacja
    EXPECT_THROW(TrustStore::check_and_remember(m_peer, m_keyA, "ML-DSA-65"),
                 std::runtime_error);
}
