#include <gtest/gtest.h>
#include "crypto/ProfileManager.h"
#include "crypto/IdentityManager.h"
#include "test_util.h"

namespace fs = std::filesystem;

class ProfileTest : public ::testing::Test {
protected:
    void SetUp() override {
        m_tmp = std::make_unique<TempDir>("quill_prof");
        ::setenv("QUILL_PROFILES_DIR", m_tmp->path().c_str(), 1);
    }
    void TearDown() override {
        ProfileManager::logout();
        ::unsetenv("QUILL_PROFILES_DIR");
    }
    std::unique_ptr<TempDir> m_tmp;
};

TEST_F(ProfileTest, CreateAndUnlockEncrypted) {
    auto created = ProfileManager::create("alice", "tajne");
    EXPECT_TRUE(created.encrypted);
    EXPECT_FALSE(created.fingerprint.empty());

    auto unlocked = ProfileManager::unlock("alice", "tajne");
    EXPECT_EQ(unlocked.fingerprint, created.fingerprint);
}

TEST_F(ProfileTest, WrongPassphraseRejected) {
    ProfileManager::create("alice", "tajne");
    EXPECT_THROW(ProfileManager::unlock("alice", "zle"), std::runtime_error);
}

TEST_F(ProfileTest, EmptyPassphraseAllowed) {
    auto created = ProfileManager::create("bob", "");
    EXPECT_FALSE(created.encrypted);
    auto unlocked = ProfileManager::unlock("bob", "");
    EXPECT_EQ(unlocked.fingerprint, created.fingerprint);
}

TEST_F(ProfileTest, DuplicateNameRejected) {
    ProfileManager::create("alice", "x");
    EXPECT_THROW(ProfileManager::create("alice", "y"), std::runtime_error);
}

TEST_F(ProfileTest, PathTraversalAndBadNamesRejected) {
    for (const char* name : {"../evil", "a b", "", "a/b", "zażółć"})
        EXPECT_THROW(ProfileManager::create(name, "x"), std::runtime_error)
            << "nazwa: " << name;
}

TEST_F(ProfileTest, ListShowsAllProfiles) {
    ProfileManager::create("alice", "x");
    ProfileManager::create("bob", "");
    auto profiles = ProfileManager::list();
    EXPECT_EQ(profiles.size(), 2u);
}

TEST_F(ProfileTest, FailedCreateLeavesNoResidue) {
    EXPECT_THROW(ProfileManager::create("../evil", "x"), std::runtime_error);
    EXPECT_TRUE(ProfileManager::list().empty());
}

TEST_F(ProfileTest, UnknownProfileRejected) {
    EXPECT_THROW(ProfileManager::unlock("ghost", "x"), std::runtime_error);
}
