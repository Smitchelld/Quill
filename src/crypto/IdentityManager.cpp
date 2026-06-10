#include "IdentityManager.h"
#include "Argon2.h"
#include "AesGcm.h"

#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <mutex>
#include <optional>
#include <stdexcept>

namespace fs = std::filesystem;

// Formaty pliku tożsamości (binarne, little-endian):
//  QID1 (plaintext): magic | pub_len u32 | pub | sec_len u32 | sec |
//                    sha3_256(payload) (32B; starsze pliki bez sumy są
//                    akceptowane — wykrywane po dokładnym rozmiarze)
//  QID2 (encrypted): magic | salt_len u32 | salt | t u32 | m_kib u32 |
//                    lanes u32 | nonce(12B) | enc_len u32 | enc
//                    gdzie enc = AES-256-GCM(payload QID1-style) || tag
//                    (integralność gwarantuje tag GCM)
static constexpr char     MAGIC_V1[4]  = {'Q', 'I', 'D', '1'};
static constexpr char     MAGIC_V2[4]  = {'Q', 'I', 'D', '2'};
static constexpr uint32_t MAX_KEY_LEN  = 16 * 1024;
static constexpr uint32_t MAX_SALT_LEN = 64;

// ── Stan aktywnego profilu ────────────────────────────────────────
static std::mutex                              g_mtx;
static std::map<std::string, SignatureKeyPair> g_cache;
static std::optional<fs::path>                 g_active_dir;
static std::string                             g_passphrase;

static void cleanse_cache_locked() {
    for (auto& [algo, kp] : g_cache)
        if (!kp.secret_key.empty())
            OPENSSL_cleanse(kp.secret_key.data(), kp.secret_key.size());
    g_cache.clear();
}

void IdentityManager::activate(const fs::path& dir, const std::string& passphrase) {
    std::lock_guard lk(g_mtx);
    cleanse_cache_locked();
    if (!g_passphrase.empty())
        OPENSSL_cleanse(g_passphrase.data(), g_passphrase.size());
    g_active_dir = dir;
    g_passphrase = passphrase;
}

void IdentityManager::deactivate() {
    std::lock_guard lk(g_mtx);
    cleanse_cache_locked();
    if (!g_passphrase.empty())
        OPENSSL_cleanse(g_passphrase.data(), g_passphrase.size());
    g_passphrase.clear();
    g_active_dir.reset();
}

fs::path IdentityManager::identity_dir() {
    {
        std::lock_guard lk(g_mtx);
        if (g_active_dir) return *g_active_dir;
    }
    if (const char* env = std::getenv("QUILL_IDENTITY_DIR"); env && *env)
        return fs::path(env);
    const char* home = std::getenv("HOME");
    if (!home || !*home)
        throw std::runtime_error("Identity: brak aktywnego profilu, $HOME i $QUILL_IDENTITY_DIR");
    return fs::path(home) / ".quill" / "identity";
}

static fs::path key_path(const std::string& algo_name) {
    return IdentityManager::identity_dir() / (algo_name + ".id");
}

// ── SERIALIZACJA ──────────────────────────────────────────────────

static void append_u32(Bytes& out, uint32_t v) {
    out.push_back(v & 0xFF);
    out.push_back((v >> 8) & 0xFF);
    out.push_back((v >> 16) & 0xFF);
    out.push_back((v >> 24) & 0xFF);
}

static uint32_t read_u32(const Bytes& in, size_t off) {
    return  static_cast<uint32_t>(in[off])
         | (static_cast<uint32_t>(in[off + 1]) << 8)
         | (static_cast<uint32_t>(in[off + 2]) << 16)
         | (static_cast<uint32_t>(in[off + 3]) << 24);
}

static Bytes sha3_256(const Bytes& data) {
    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (EVP_Digest(data.data(), data.size(), digest, &len,
                   EVP_sha3_256(), nullptr) != 1)
        throw std::runtime_error("Identity: SHA-3-256 nie powiodl sie");
    return Bytes(digest, digest + len);
}

static Bytes build_payload(const SignatureKeyPair& kp) {
    Bytes payload;
    append_u32(payload, static_cast<uint32_t>(kp.public_key.size()));
    payload.insert(payload.end(), kp.public_key.begin(), kp.public_key.end());
    append_u32(payload, static_cast<uint32_t>(kp.secret_key.size()));
    payload.insert(payload.end(), kp.secret_key.begin(), kp.secret_key.end());
    return payload;
}

static SignatureKeyPair parse_payload(const Bytes& payload, size_t base_off,
                                      size_t total_size) {
    size_t off = base_off;
    if (off + 4 > total_size)
        throw std::runtime_error("Identity: uszkodzony plik klucza (payload)");
    uint32_t pub_len = read_u32(payload, off); off += 4;
    if (pub_len > MAX_KEY_LEN || off + pub_len + 4 > total_size)
        throw std::runtime_error("Identity: uszkodzony plik klucza (pub_len)");
    Bytes pub(payload.begin() + off, payload.begin() + off + pub_len);
    off += pub_len;

    uint32_t sec_len = read_u32(payload, off); off += 4;
    if (sec_len > MAX_KEY_LEN || off + sec_len != total_size)
        throw std::runtime_error("Identity: uszkodzony plik klucza (sec_len)");
    Bytes sec(payload.begin() + off, payload.begin() + off + sec_len);

    return {std::move(pub), std::move(sec)};
}

// ── ZAPIS ─────────────────────────────────────────────────────────

static void write_file_0600(const fs::path& path, const Bytes& blob) {
    fs::create_directories(path.parent_path());
    ::chmod(path.parent_path().c_str(), 0700);

    fs::path tmp = path;
    tmp += ".tmp";
    ::unlink(tmp.c_str());

    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0)
        throw std::runtime_error("Identity: nie mozna utworzyc pliku klucza: " + tmp.string());

    const uint8_t* p = blob.data();
    size_t left = blob.size();
    while (left > 0) {
        ssize_t n = ::write(fd, p, left);
        if (n <= 0) {
            ::close(fd);
            ::unlink(tmp.c_str());
            throw std::runtime_error("Identity: blad zapisu klucza");
        }
        p += n;
        left -= static_cast<size_t>(n);
    }
    ::fsync(fd);
    ::close(fd);

    if (::rename(tmp.c_str(), path.c_str()) != 0) {
        ::unlink(tmp.c_str());
        throw std::runtime_error("Identity: blad rename przy zapisie klucza");
    }
}

// passphrase pusty => QID1 (plaintext), inaczej QID2 (Argon2id + AES-GCM)
static void save_keypair(const fs::path& path, const SignatureKeyPair& kp,
                         const std::string& passphrase) {
    Bytes payload = build_payload(kp);
    Bytes blob;

    if (passphrase.empty()) {
        // Plaintext: integralność zapewnia suma SHA-3-256 na końcu pliku
        Bytes checksum = sha3_256(payload);
        blob.insert(blob.end(), MAGIC_V1, MAGIC_V1 + 4);
        blob.insert(blob.end(), payload.begin(), payload.end());
        blob.insert(blob.end(), checksum.begin(), checksum.end());
    } else {
        Bytes salt = Argon2::random_salt();
        Bytes aes_key = Argon2::derive(passphrase, salt,
                                       Argon2::T_COST, Argon2::M_COST_KIB,
                                       Argon2::LANES);
        EncryptedData enc = AesGcm::encrypt(aes_key, payload);
        OPENSSL_cleanse(aes_key.data(), aes_key.size());

        blob.insert(blob.end(), MAGIC_V2, MAGIC_V2 + 4);
        append_u32(blob, static_cast<uint32_t>(salt.size()));
        blob.insert(blob.end(), salt.begin(), salt.end());
        append_u32(blob, Argon2::T_COST);
        append_u32(blob, Argon2::M_COST_KIB);
        append_u32(blob, Argon2::LANES);
        blob.insert(blob.end(), enc.nonce.begin(), enc.nonce.end());
        append_u32(blob, static_cast<uint32_t>(enc.ciphertext.size()));
        blob.insert(blob.end(), enc.ciphertext.begin(), enc.ciphertext.end());
    }

    OPENSSL_cleanse(payload.data(), payload.size());
    write_file_0600(path, blob);
}

// ── ODCZYT ────────────────────────────────────────────────────────

struct LoadedKey {
    SignatureKeyPair kp;
    bool             was_plaintext = false; // QID1 -> kandydat do migracji
};

static LoadedKey load_keypair(const fs::path& path, const std::string& passphrase,
                              size_t expect_pub, size_t expect_sec) {
    // Jak OpenSSH: odmowa użycia klucza czytelnego dla grupy/innych
    struct stat st{};
    if (::stat(path.c_str(), &st) != 0)
        throw std::runtime_error("Identity: stat() nie powiodl sie: " + path.string());
    if ((st.st_mode & 077) != 0)
        throw std::runtime_error(
            "Identity: plik klucza " + path.string() +
            " ma zbyt szerokie uprawnienia (wymagane 0600) — odmowa uzycia");

    std::ifstream f(path, std::ios::binary);
    Bytes blob((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    if (!f.good() && !f.eof())
        throw std::runtime_error("Identity: blad odczytu pliku klucza");
    if (blob.size() < 12)
        throw std::runtime_error("Identity: plik klucza za krotki");

    LoadedKey result;

    if (std::memcmp(blob.data(), MAGIC_V1, 4) == 0) {
        // Rozmiar pliku jest deterministyczny dla danego algorytmu:
        // base (legacy, bez sumy) lub base+32 (z suma SHA-3-256)
        const size_t base = 4 + 4 + expect_pub + 4 + expect_sec;
        if (blob.size() == base + 32) {
            Bytes payload(blob.begin() + 4, blob.begin() + base);
            Bytes stored_sum(blob.begin() + base, blob.end());
            if (sha3_256(payload) != stored_sum)
                throw std::runtime_error(
                    "Identity: suma kontrolna klucza " + path.string() +
                    " nie zgadza sie — plik uszkodzony lub podmieniony");
            result.kp = parse_payload(blob, 4, base);
        } else if (blob.size() == base) {
            result.kp = parse_payload(blob, 4, blob.size()); // legacy bez sumy
        } else {
            throw std::runtime_error("Identity: nieprawidlowy rozmiar pliku QID1");
        }
        result.was_plaintext = true;
    } else if (std::memcmp(blob.data(), MAGIC_V2, 4) == 0) {
        if (passphrase.empty())
            throw std::runtime_error(
                "Identity: klucz " + path.string() +
                " jest zaszyfrowany — wymagany passphrase");

        size_t off = 4;
        uint32_t salt_len = read_u32(blob, off); off += 4;
        if (salt_len == 0 || salt_len > MAX_SALT_LEN || off + salt_len + 12 + 12 + 4 > blob.size())
            throw std::runtime_error("Identity: uszkodzony plik klucza (salt)");
        Bytes salt(blob.begin() + off, blob.begin() + off + salt_len);
        off += salt_len;

        uint32_t t_cost = read_u32(blob, off); off += 4;
        uint32_t m_kib  = read_u32(blob, off); off += 4;
        uint32_t lanes  = read_u32(blob, off); off += 4;

        Bytes nonce(blob.begin() + off, blob.begin() + off + AesGcm::IV_LEN);
        off += AesGcm::IV_LEN;

        uint32_t enc_len = read_u32(blob, off); off += 4;
        if (off + enc_len != blob.size())
            throw std::runtime_error("Identity: uszkodzony plik klucza (enc_len)");
        Bytes enc(blob.begin() + off, blob.end());

        Bytes aes_key = Argon2::derive(passphrase, salt, t_cost, m_kib, lanes);
        Bytes payload;
        try {
            payload = AesGcm::decrypt_bytes(aes_key, nonce, enc);
        } catch (const std::exception&) {
            OPENSSL_cleanse(aes_key.data(), aes_key.size());
            // GCM tag mismatch: złe hasło albo zmanipulowany plik —
            // celowo jeden komunikat (nierozróżnialne bez dodatkowych zalozen)
            throw std::runtime_error(
                "Identity: bledny passphrase lub uszkodzony plik klucza");
        }
        OPENSSL_cleanse(aes_key.data(), aes_key.size());

        result.kp = parse_payload(payload, 0, payload.size());
        OPENSSL_cleanse(payload.data(), payload.size());
    } else {
        throw std::runtime_error("Identity: nieprawidlowy format pliku klucza (magic)");
    }

    // Długości muszą zgadzać się z algorytmem — inny algorytm/obcięty plik = błąd
    if (result.kp.public_key.size() != expect_pub || result.kp.secret_key.size() != expect_sec)
        throw std::runtime_error(
            "Identity: dlugosci kluczy w " + path.string() +
            " nie pasuja do algorytmu — plik uszkodzony lub podmieniony");

    return result;
}

// ── API ───────────────────────────────────────────────────────────

SignatureKeyPair IdentityManager::load_or_generate(const std::string& level) {
    DilithiumSign signer(level);
    const std::string algo = signer.algo_name();

    std::string passphrase;
    {
        std::lock_guard lk(g_mtx);
        if (auto it = g_cache.find(algo); it != g_cache.end())
            return it->second;
        passphrase = g_passphrase;
    }

    const fs::path path = key_path(algo);
    SignatureKeyPair kp;

    if (fs::exists(path)) {
        LoadedKey loaded = load_keypair(path, passphrase,
                                        signer.pub_key_len(), signer.sec_key_len());
        kp = std::move(loaded.kp);

        // Self-test: uszkodzony/podmieniony klucz ma zawieść tutaj,
        // a nie cichą regeneracją (zmiana tożsamości = sygnał ataku)
        static const Bytes probe = {'q','u','i','l','l','-','s','e','l','f','t','e','s','t'};
        Bytes sig = signer.sign(probe, kp.secret_key);
        if (!signer.verify(probe, sig, kp.public_key))
            throw std::runtime_error(
                "Identity: self-test klucza " + path.string() +
                " nie powiodl sie — klucz uszkodzony, wymagana interwencja uzytkownika");

        // Migracja w miejscu: QID1 + aktywny passphrase => podnieś do QID2
        if (loaded.was_plaintext && !passphrase.empty())
            save_keypair(path, kp, passphrase);
    } else {
        kp = signer.generate_keypair();
        save_keypair(path, kp, passphrase);
    }

    std::lock_guard lk(g_mtx);
    g_cache[algo] = kp;
    return kp;
}

std::string IdentityManager::fingerprint(const Bytes& public_key) {
    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    if (EVP_Digest(public_key.data(), public_key.size(),
                   digest, &digest_len, EVP_sha3_256(), nullptr) != 1
        || digest_len < 12)
        throw std::runtime_error("Identity: SHA-3-256 fingerprint nie powiodl sie");

    // 12 bajtów (96 bitów) w 6 grupach: A3F2-9C1B-44DE-F021-8B3C-7A09
    static const char* HEX = "0123456789ABCDEF";
    std::string fp;
    for (size_t i = 0; i < 12; ++i) {
        if (i > 0 && i % 2 == 0) fp += '-';
        fp += HEX[digest[i] >> 4];
        fp += HEX[digest[i] & 0x0F];
    }
    return fp;
}
