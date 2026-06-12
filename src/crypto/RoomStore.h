#ifndef QUILL_ROOMSTORE_H
#define QUILL_ROOMSTORE_H

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

struct RoomInfo {
    std::string name;
    bool        password_protected = false;
};

// Trwałe pokoje per profil: <profile_dir>/rooms.json
// Haslo chronione pokoje: Argon2id verifier (salt + hash w JSON).
class RoomStore {
public:
    static void activate(const std::filesystem::path& profile_dir);
    static void deactivate();

    static std::vector<RoomInfo> list();
    static bool exists(const std::string& name);
    static bool is_protected(const std::string& name);

    // password pusty => pokoj otwarty; rzuca jesli pokoj juz istnieje
    static void add(const std::string& name, const std::string& password = "");

    static void remove(const std::string& name);

    static bool verify_password(const std::string& name, const std::string& password);

    static std::filesystem::path store_path();
};

#endif
