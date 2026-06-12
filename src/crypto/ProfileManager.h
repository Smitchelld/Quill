#ifndef QUILL_PROFILEMANAGER_H
#define QUILL_PROFILEMANAGER_H

#include <filesystem>
#include <string>
#include <vector>

struct ProfileInfo {
    std::string           name;
    std::string           fingerprint;
    bool                  encrypted = false;
    std::filesystem::path dir;
};

class ProfileManager {
public:
    static constexpr size_t MIN_PASSPHRASE_LEN = 8;

    static std::filesystem::path profiles_root();
    static std::vector<ProfileInfo> list();
    static ProfileInfo create(const std::string& name, const std::string& passphrase);
    static ProfileInfo unlock(const std::string& name, const std::string& passphrase);
    static void logout();
    static void remove(const std::string& name, const std::string& passphrase);
    static std::filesystem::path active_dir();
};

#endif // QUILL_PROFILEMANAGER_H
