#include <gtest/gtest.h>
#include "crypto/RoomStore.h"
#include "crypto/ProfileManager.h"
#include "test_util.h"

namespace fs = std::filesystem;

class RoomStoreTest : public ::testing::Test {
protected:
    void SetUp() override {
        m_tmp = std::make_unique<TempDir>("quill_room");
        ::setenv("QUILL_PROFILES_DIR", m_tmp->path().c_str(), 1);
        auto p = ProfileManager::create("host", "hostpass12");
        m_dir = p.dir;
        RoomStore::activate(m_dir);
    }
    void TearDown() override {
        RoomStore::deactivate();
        ProfileManager::logout();
        ::unsetenv("QUILL_PROFILES_DIR");
    }
    std::unique_ptr<TempDir> m_tmp;
    fs::path m_dir;
};

TEST_F(RoomStoreTest, DefaultGeneralExists) {
    auto rooms = RoomStore::list();
    ASSERT_FALSE(rooms.empty());
    EXPECT_EQ(rooms[0].name, "general");
    EXPECT_FALSE(rooms[0].password_protected);
}

TEST_F(RoomStoreTest, ProtectedRoomVerify) {
    RoomStore::add("secret", "roompass12");
    EXPECT_TRUE(RoomStore::is_protected("secret"));
    EXPECT_TRUE(RoomStore::verify_password("secret", "roompass12"));
    EXPECT_FALSE(RoomStore::verify_password("secret", "wrongpass1"));
}

TEST_F(RoomStoreTest, PersistsAcrossReload) {
    RoomStore::add("team", "teampass12");
    RoomStore::deactivate();
    RoomStore::activate(m_dir);
    EXPECT_TRUE(RoomStore::exists("team"));
    EXPECT_TRUE(RoomStore::verify_password("team", "teampass12"));
}

TEST_F(RoomStoreTest, DuplicateAddThrows) {
    RoomStore::add("dup", "");
    EXPECT_THROW(RoomStore::add("dup", ""), std::runtime_error);
}

TEST_F(RoomStoreTest, RemoveRoom) {
    RoomStore::add("temp", "");
    RoomStore::remove("temp");
    EXPECT_FALSE(RoomStore::exists("temp"));
}

TEST_F(RoomStoreTest, CannotRemoveGeneral) {
    EXPECT_THROW(RoomStore::remove("general"), std::runtime_error);
}
