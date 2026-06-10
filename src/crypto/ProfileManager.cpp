#include "ProfileManager.h"
#include "IdentityManager.h"

#include <nlohmann/json.hpp>
#include <sys/stat.h>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <stdexcept>

namespace fs = std::filesystem;
using json = nlohmann::json;

static constexpr size_t MAX_NAME_LEN = 32;

// Nazwa profilu jest nazwą katalogu — whitelist zamiast escapowania
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
    // Odrzucamy np. "aaaaaaaa" — zerowa entropia mimo długości
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
        } catch (const std::exception&) {
            // Uszkodzony profile.json — pomijamy na liście, nie wywracamy UI
        }
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

    // Generacja tożsamości BALANCED od razu:
    //  1. logowanie ma co weryfikować passphrase'em,
    //  2. fingerprint jest znany od chwili utworzenia profilu
    IdentityManager::activate(dir / "identity", passphrase);
    try {
        auto kp = IdentityManager::load_or_generate("BALANCED");

        ProfileInfo info;
        info.name        = name;
        info.fingerprint = IdentityManager::fingerprint(kp.public_key);
        info.encrypted   = true;
        info.dir         = dir;
        write_meta(info);
        return info;
    } catch (...) {
        IdentityManager::deactivate();
        fs::remove_all(dir); // nie zostawiamy profilu w połowie utworzonego
        throw;
    }
}

ProfileInfo ProfileManager::unlock(const std::string& name, const std::string& passphrase) {
    validate_name(name);

    fs::path dir = profiles_root() / name;
    ProfileInfo info = read_meta(dir);

    IdentityManager::activate(dir / "identity", passphrase);
    try {
        // Weryfikacja passphrase'a: odszyfrowanie (GCM tag) + self-test klucza.
        // Przy okazji odświeżamy fingerprint w metadanych, gdyby ich brakowało.
        auto kp = IdentityManager::load_or_generate("BALANCED");
        std::string fp = IdentityManager::fingerprint(kp.public_key);
        if (info.fingerprint != fp) {
            info.fingerprint = fp;
            write_meta(info);
        }
        return info;
    } catch (...) {
        IdentityManager::deactivate(); // nieudane logowanie nie zostawia stanu
        throw;
    }
}

void ProfileManager::logout() {
    IdentityManager::deactivate();
}
