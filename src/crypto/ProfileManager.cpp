#include "ProfileManager.h"
#include "IdentityManager.h"
#include "RoomStore.h"

#include <nlohmann/json.hpp>
#include <sys/stat.h>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <stdexcept>
#include <signal.h>
#include <unistd.h>

namespace fs = std::filesystem;
using json = nlohmann::json;

static constexpr size_t MAX_NAME_LEN = 32;
static fs::path g_active_dir;

static fs::path session_lock_path(const fs::path& profile_dir) {
    return profile_dir / ".session.lock";
}

static bool pid_alive(pid_t pid) {
    if (pid <= 0) return false;
    return ::kill(pid, 0) == 0;
}

static void acquire_session_lock(const fs::path& profile_dir) {
    fs::path lock = session_lock_path(profile_dir);
    if (fs::exists(lock)) {
        std::ifstream f(lock);
        pid_t other = 0;
        f >> other;
        if (other == ::getpid())
            return;
        if (pid_alive(other))
            throw std::runtime_error(
                "Profil jest juz zalogowany w innej instancji Quill (PID " +
                std::to_string(other) + ")");
        fs::remove(lock);
    }
    std::ofstream f(lock, std::ios::trunc);
    if (!f)
        throw std::runtime_error("Profil: nie mozna utworzyc blokady sesji");
    f << ::getpid();
    ::chmod(lock.c_str(), 0600);
}

static void release_session_lock(const fs::path& profile_dir) {
    if (profile_dir.empty()) return;
    fs::path lock = session_lock_path(profile_dir);
    if (!fs::exists(lock)) return;
    std::ifstream f(lock);
    pid_t stored = 0;
    f >> stored;
    if (stored == ::getpid() || stored == 0)
        fs::remove(lock);
}

static void validate_name(const std::string& name) {
    if (name.empty() || name.size() > MAX_NAME_LEN)
        throw std::runtime_error("Profil: nazwa musi miec 1-32 znaki");
    for (char c : name)
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_' && c != '-')
            throw std::runtime_error(
                "Profil: dozwolone znaki w nazwie to [a-zA-Z0-9_-]");
}

static void validate_passphrase(const std::string& passphrase) {
    if (passphrase.size() < ProfileManager::MIN_PASSPHRASE_LEN)
        throw std::runtime_error(
            "Passphrase musi miec minimum " +
            std::to_string(ProfileManager::MIN_PASSPHRASE_LEN) + " znakow");
    bool all_same = true;
    for (size_t i = 1; i < passphrase.size(); ++i) {
        if (passphrase[i] != passphrase[0]) { all_same = false; break; }
    }
    if (all_same)
        throw std::runtime_error("Passphrase jest zbyt slaby (powtarzajacy sie znak)");
}

fs::path ProfileManager::profiles_root() {
    if (const char* env = std::getenv("QUILL_PROFILES_DIR"); env && *env)
        return fs::path(env);
    const char* home = std::getenv("HOME");
    if (!home || !*home)
        throw std::runtime_error("Profil: brak $HOME i $QUILL_PROFILES_DIR");
    return fs::path(home) / ".quill" / "profiles";
}

static fs::path meta_path(const fs::path& profile_dir) {
    return profile_dir / "profile.json";
}

static ProfileInfo read_meta(const fs::path& profile_dir) {
    std::ifstream f(meta_path(profile_dir));
    if (!f)
        throw std::runtime_error("Profil: brak profile.json w " + profile_dir.string());
    json j = json::parse(f);

    ProfileInfo info;
    info.name        = j.at("name").get<std::string>();
    info.fingerprint = j.value("fingerprint", "");
    info.encrypted   = j.value("encrypted", false);
    info.dir         = profile_dir;
    return info;
}

static void write_meta(const ProfileInfo& info) {
    json j;
    j["name"]        = info.name;
    j["fingerprint"] = info.fingerprint;
    j["encrypted"]   = info.encrypted;

    std::ofstream f(meta_path(info.dir), std::ios::trunc);
    if (!f)
        throw std::runtime_error("Profil: nie mozna zapisac profile.json");
    f << j.dump(2);
}

std::vector<ProfileInfo> ProfileManager::list() {
    std::vector<ProfileInfo> out;
    fs::path root = profiles_root();
    if (!fs::exists(root)) return out;

    for (const auto& entry : fs::directory_iterator(root)) {
        if (!entry.is_directory()) continue;
        if (!fs::exists(meta_path(entry.path()))) continue;
        try {
            out.push_back(read_meta(entry.path()));
        } catch (const std::exception&) {}
    }
    return out;
}

ProfileInfo ProfileManager::create(const std::string& name, const std::string& passphrase) {
    validate_name(name);
    validate_passphrase(passphrase);

    fs::path dir = profiles_root() / name;
    if (fs::exists(dir))
        throw std::runtime_error("Profil '" + name + "' juz istnieje");

    fs::create_directories(dir / "identity");
    ::chmod(profiles_root().c_str(), 0700);
    ::chmod(dir.c_str(), 0700);

    IdentityManager::activate(dir / "identity", passphrase);
    try {
        auto kp = IdentityManager::load_or_generate("BALANCED");

        ProfileInfo info;
        info.name        = name;
        info.fingerprint = IdentityManager::fingerprint(kp.public_key);
        info.encrypted   = true;
        info.dir         = dir;
        write_meta(info);
        acquire_session_lock(dir);
        g_active_dir = dir;
        RoomStore::activate(dir);
        return info;
    } catch (...) {
        IdentityManager::deactivate();
        fs::remove_all(dir);
        throw;
    }
}

ProfileInfo ProfileManager::unlock(const std::string& name, const std::string& passphrase) {
    validate_name(name);

    fs::path dir = profiles_root() / name;
    ProfileInfo info = read_meta(dir);

    IdentityManager::activate(dir / "identity", passphrase);
    try {
        auto kp = IdentityManager::load_or_generate("BALANCED");
        std::string fp = IdentityManager::fingerprint(kp.public_key);
        if (info.fingerprint != fp) {
            info.fingerprint = fp;
            write_meta(info);
        }
        acquire_session_lock(dir);
        g_active_dir = dir;
        RoomStore::activate(dir);
        return info;
    } catch (...) {
        IdentityManager::deactivate();
        throw;
    }
}

void ProfileManager::logout() {
    release_session_lock(g_active_dir);
    RoomStore::deactivate();
    g_active_dir.clear();
    IdentityManager::deactivate();
}

void ProfileManager::remove(const std::string& name, const std::string& passphrase) {
    validate_name(name);
    fs::path dir = profiles_root() / name;
    if (!fs::exists(dir))
        throw std::runtime_error("Profil '" + name + "' nie istnieje");

    bool was_active = (!g_active_dir.empty() && fs::equivalent(g_active_dir, dir));

    IdentityManager::activate(dir / "identity", passphrase);
    try {
        IdentityManager::load_or_generate("BALANCED");
    } catch (...) {
        IdentityManager::deactivate();
        throw std::runtime_error("Zle haslo — nie mozna usunac profilu");
    }
    IdentityManager::deactivate();
    release_session_lock(dir);
    if (was_active) {
        g_active_dir.clear();
        RoomStore::deactivate();
    }
    fs::remove_all(dir);
}

fs::path ProfileManager::active_dir() {
    return g_active_dir;
}
