#include "TrustStore.h"
#include "IdentityManager.h"

#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <fstream>
#include <mutex>
#include <stdexcept>

namespace fs = std::filesystem;
using json = nlohmann::json;

// Dostęp z wątków handshake'u i UI — jeden mutex na cały store
static std::mutex g_mtx;

const char* TrustStore::state_name(TrustState s) {
    switch (s) {
        case TrustState::UNVERIFIED: return "UNVERIFIED";
        case TrustState::KNOWN:      return "KNOWN";
        case TrustState::VERIFIED:   return "VERIFIED";
        case TrustState::MISMATCH:   return "MISMATCH";
    }
    return "?";
}

fs::path TrustStore::store_path() {
    // <profil>/identity -> <profil>/known_hosts
    return IdentityManager::identity_dir().parent_path() / "known_hosts";
}

// Pełny SHA-3-256 klucza publicznego (64 hex) — do porównań.
// Skrócony fingerprint (96b) służy tylko do wyświetlania.
static std::string full_key_hash(const Bytes& public_key) {
    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (EVP_Digest(public_key.data(), public_key.size(),
                   digest, &len, EVP_sha3_256(), nullptr) != 1)
        throw std::runtime_error("TrustStore: SHA-3-256 nie powiodl sie");
    static const char* HEX = "0123456789abcdef";
    std::string out;
    for (unsigned int i = 0; i < len; ++i) {
        out += HEX[digest[i] >> 4];
        out += HEX[digest[i] & 0x0F];
    }
    return out;
}

static json load_store_locked() {
    std::ifstream f(TrustStore::store_path());
    if (!f) return json::object();
    try {
        return json::parse(f);
    } catch (const std::exception&) {
        // Uszkodzony known_hosts to incydent bezpieczeństwa — nie nadpisujemy
        // go cicho pustym plikiem, tylko zatrzymujemy łączenie
        throw std::runtime_error(
            "TrustStore: known_hosts uszkodzony (" +
            TrustStore::store_path().string() + ") — wymagana interwencja");
    }
}

static void save_store_locked(const json& j) {
    fs::path path = TrustStore::store_path();
    fs::create_directories(path.parent_path());

    fs::path tmp = path;
    tmp += ".tmp";
    {
        std::ofstream f(tmp, std::ios::trunc);
        if (!f) throw std::runtime_error("TrustStore: nie mozna zapisac known_hosts");
        f << j.dump(2);
    }
    ::chmod(tmp.c_str(), 0600);
    fs::rename(tmp, path);
}

TrustDecision TrustStore::check_and_remember(const std::string& peer_id,
                                             const Bytes& public_key,
                                             const std::string& algo,
                                             bool allow_algo_rotation) {
    std::lock_guard lk(g_mtx);

    std::string hash = full_key_hash(public_key);
    std::string fp   = IdentityManager::fingerprint(public_key);

    json store = load_store_locked();

    if (!store.contains(peer_id)) {
        // TOFU: pierwszy kontakt — zapamiętujemy, ale NIE ufamy w pełni
        store[peer_id] = {
            {"key_sha3",    hash},
            {"fingerprint", fp},
            {"algo",        algo},
            {"verified",    false},
        };
        save_store_locked(store);
        return {TrustState::UNVERIFIED, fp, ""};
    }

    const json& entry = store[peer_id];
    std::string stored_hash = entry.at("key_sha3").get<std::string>();
    std::string stored_fp   = entry.value("fingerprint", "");

    if (stored_hash != hash) {
        std::string stored_algo = entry.value("algo", "");
        if (allow_algo_rotation && stored_algo != algo) {
            bool was_verified = entry.value("verified", false);
            store[peer_id] = {
                {"key_sha3",    hash},
                {"fingerprint", fp},
                {"algo",        algo},
                {"verified",    was_verified},
            };
            save_store_locked(store);
            return {was_verified ? TrustState::VERIFIED : TrustState::KNOWN,
                    fp, stored_fp};
        }
        // Zmiana klucza = potencjalny MITM. Wpis zostaje nietknięty.
        return {TrustState::MISMATCH, fp, stored_fp};
    }

    bool verified = entry.value("verified", false);
    return {verified ? TrustState::VERIFIED : TrustState::KNOWN, fp, stored_fp};
}

void TrustStore::mark_verified(const std::string& peer_id) {
    std::lock_guard lk(g_mtx);
    json store = load_store_locked();
    if (!store.contains(peer_id))
        throw std::runtime_error("TrustStore: nieznany peer: " + peer_id);
    store[peer_id]["verified"] = true;
    save_store_locked(store);
}

void TrustStore::remove(const std::string& peer_id) {
    std::lock_guard lk(g_mtx);
    json store = load_store_locked();
    store.erase(peer_id);
    save_store_locked(store);
}

std::vector<TrustEntry> TrustStore::list() {
    std::lock_guard lk(g_mtx);
    json store = load_store_locked();

    std::vector<TrustEntry> out;
    for (auto& [peer_id, entry] : store.items()) {
        TrustEntry e;
        e.peer_id     = peer_id;
        e.fingerprint = entry.value("fingerprint", "");
        e.algo        = entry.value("algo", "");
        e.verified    = entry.value("verified", false);
        out.push_back(std::move(e));
    }
    return out;
}
