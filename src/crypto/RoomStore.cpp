#include "RoomStore.h"
#include "Argon2.h"

#include <nlohmann/json.hpp>
#include <cctype>
#include <fstream>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;
using json = nlohmann::json;

static fs::path g_profile_dir;
static constexpr const char* ROOMS_FILE = "rooms.json";

static void validate_room_name(const std::string& name) {
    if (name.empty() || name.size() > 32)
        throw std::runtime_error("Pokoj: nazwa musi miec 1-32 znaki");
    for (char c : name) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_' && c != '-')
            throw std::runtime_error(
                "Pokoj: dozwolone znaki w nazwie to [a-zA-Z0-9_-]");
    }
}

static json load_json() {
    fs::path path = RoomStore::store_path();
    if (!fs::exists(path)) {
        json j;
        j["rooms"] = json::array({
            {{"name", "general"}, {"protected", false}}
        });
        return j;
    }
    std::ifstream f(path);
    if (!f)
        throw std::runtime_error("Pokoj: nie mozna odczytac rooms.json");
    return json::parse(f);
}

static void save_json(const json& j) {
    fs::path path = RoomStore::store_path();
    fs::path tmp = path;
    tmp += ".tmp";
    {
        std::ofstream f(tmp, std::ios::trunc);
        if (!f)
            throw std::runtime_error("Pokoj: nie mozna zapisac rooms.json");
        f << j.dump(2);
    }
    fs::rename(tmp, path);
    ::chmod(path.c_str(), 0600);
}

void RoomStore::activate(const fs::path& profile_dir) {
    g_profile_dir = profile_dir;
    if (!fs::exists(store_path()))
        save_json(load_json()); // utworz domyslny general
}

void RoomStore::deactivate() {
    g_profile_dir.clear();
}

fs::path RoomStore::store_path() {
    if (g_profile_dir.empty())
        throw std::runtime_error("Pokoj: brak aktywnego profilu");
    return g_profile_dir / ROOMS_FILE;
}

std::vector<RoomInfo> RoomStore::list() {
    json j = load_json();
    std::vector<RoomInfo> out;
    for (const auto& r : j.at("rooms")) {
        RoomInfo info;
        info.name = r.at("name").get<std::string>();
        info.password_protected = r.value("protected", false);
        out.push_back(std::move(info));
    }
    return out;
}

bool RoomStore::exists(const std::string& name) {
    for (const auto& r : list())
        if (r.name == name) return true;
    return false;
}

bool RoomStore::is_protected(const std::string& name) {
    json j = load_json();
    for (const auto& r : j.at("rooms")) {
        if (r.at("name").get<std::string>() == name)
            return r.value("protected", false);
    }
    return false;
}

void RoomStore::add(const std::string& name, const std::string& password) {
    validate_room_name(name);
    json j = load_json();
    auto& rooms = j.at("rooms");
    for (const auto& r : rooms) {
        if (r.at("name").get<std::string>() == name)
            throw std::runtime_error("Pokoj '" + name + "' juz istnieje");
    }

    json entry;
    entry["name"] = name;
    if (!password.empty()) {
        Bytes salt = Argon2::random_salt();
        Bytes hash = Argon2::derive(password, salt,
                                    Argon2::T_COST, Argon2::M_COST_KIB, Argon2::LANES);
        entry["protected"] = true;
        entry["salt"] = salt;
        entry["verifier"] = hash;
    } else {
        entry["protected"] = false;
    }
    rooms.push_back(std::move(entry));
    save_json(j);
}

void RoomStore::remove(const std::string& name) {
    if (name == "general")
        throw std::runtime_error("Nie mozna usunac pokoju general");
    json j = load_json();
    auto& rooms = j.at("rooms");
    const size_t before = rooms.size();
    for (auto it = rooms.begin(); it != rooms.end(); ) {
        if (it->at("name").get<std::string>() == name)
            it = rooms.erase(it);
        else
            ++it;
    }
    if (rooms.size() == before)
        throw std::runtime_error("Pokoj '" + name + "' nie istnieje");
    save_json(j);
}

bool RoomStore::verify_password(const std::string& name, const std::string& password) {
    json j = load_json();
    for (const auto& r : j.at("rooms")) {
        if (r.at("name").get<std::string>() != name) continue;
        if (!r.value("protected", false)) return true;
        Bytes salt = r.at("salt").get<Bytes>();
        Bytes expected = r.at("verifier").get<Bytes>();
        Bytes got = Argon2::derive(password, salt,
                                   Argon2::T_COST, Argon2::M_COST_KIB, Argon2::LANES,
                                   expected.size());
        if (got.size() != expected.size()) return false;
        volatile uint8_t diff = 0;
        for (size_t i = 0; i < got.size(); ++i)
            diff |= static_cast<uint8_t>(got[i] ^ expected[i]);
        return diff == 0;
    }
    return false;
}
