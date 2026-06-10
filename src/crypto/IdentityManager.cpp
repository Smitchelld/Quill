#include "IdentityManager.h"

#include <openssl/evp.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <mutex>
#include <stdexcept>

namespace fs = std::filesystem;

// Format pliku tożsamości (binarny, little-endian):
//   magic "QID1" (4B) | pub_len (u32) | pub | sec_len (u32) | sec
static constexpr char     FILE_MAGIC[4] = {'Q', 'I', 'D', '1'};
static constexpr uint32_t MAX_KEY_LEN   = 16 * 1024; // sanity bound

// Cache w pamięci procesu — unika I/O i self-testu przy każdym handshake'u
static std::map<std::string, SignatureKeyPair> g_cache;
static std::mutex                              g_cache_mtx;

// ── ŚCIEŻKI ───────────────────────────────────────────────────────

fs::path IdentityManager::identity_dir() {
    if (const char* env = std::getenv("QUILL_IDENTITY_DIR"); env && *env)
        return fs::path(env);
    const char* home = std::getenv("HOME");
    if (!home || !*home)
        throw std::runtime_error("Identity: brak $HOME i $QUILL_IDENTITY_DIR");
    return fs::path(home) / ".quill" / "identity";
}

static fs::path key_path(const std::string& algo_name) {
    return IdentityManager::identity_dir() / (algo_name + ".id");
}

// ── ZAPIS / ODCZYT ────────────────────────────────────────────────

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

// Zapis atomowy z uprawnieniami 0600 od momentu utworzenia pliku
static void save_keypair(const fs::path& path, const SignatureKeyPair& kp) {
    fs::create_directories(path.parent_path());
    ::chmod(path.parent_path().c_str(), 0700);

    Bytes blob;
    blob.insert(blob.end(), FILE_MAGIC, FILE_MAGIC + 4);
    append_u32(blob, static_cast<uint32_t>(kp.public_key.size()));
    blob.insert(blob.end(), kp.public_key.begin(), kp.public_key.end());
    append_u32(blob, static_cast<uint32_t>(kp.secret_key.size()));
    blob.insert(blob.end(), kp.secret_key.begin(), kp.secret_key.end());

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

static SignatureKeyPair load_keypair(const fs::path& path,
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

    if (blob.size() < 12 || std::memcmp(blob.data(), FILE_MAGIC, 4) != 0)
        throw std::runtime_error("Identity: nieprawidlowy format pliku klucza (magic)");

    size_t off = 4;
    uint32_t pub_len = read_u32(blob, off); off += 4;
    if (pub_len > MAX_KEY_LEN || off + pub_len + 4 > blob.size())
        throw std::runtime_error("Identity: uszkodzony plik klucza (pub_len)");
    Bytes pub(blob.begin() + off, blob.begin() + off + pub_len);
    off += pub_len;

    uint32_t sec_len = read_u32(blob, off); off += 4;
    if (sec_len > MAX_KEY_LEN || off + sec_len != blob.size())
        throw std::runtime_error("Identity: uszkodzony plik klucza (sec_len)");
    Bytes sec(blob.begin() + off, blob.begin() + off + sec_len);

    // Długości muszą zgadzać się z oczekiwaniami algorytmu —
    // plik z innego algorytmu / obcięty = twardy błąd
    if (pub.size() != expect_pub || sec.size() != expect_sec)
        throw std::runtime_error(
            "Identity: dlugosci kluczy w " + path.string() +
            " nie pasuja do algorytmu — plik uszkodzony lub podmieniony");

    return {std::move(pub), std::move(sec)};
}

// ── API ───────────────────────────────────────────────────────────

SignatureKeyPair IdentityManager::load_or_generate(const std::string& level) {
    DilithiumSign signer(level);
    const std::string algo = signer.algo_name();

    {
        std::lock_guard lk(g_cache_mtx);
        if (auto it = g_cache.find(algo); it != g_cache.end())
            return it->second;
    }

    const fs::path path = key_path(algo);
    SignatureKeyPair kp;

    if (fs::exists(path)) {
        kp = load_keypair(path, signer.pub_key_len(), signer.sec_key_len());

        // Self-test: uszkodzony/podmieniony klucz ma zawieść tutaj,
        // a nie cichą regeneracją (zmiana tożsamości = sygnał ataku)
        static const Bytes probe = {'q','u','i','l','l','-','s','e','l','f','t','e','s','t'};
        Bytes sig = signer.sign(probe, kp.secret_key);
        if (!signer.verify(probe, sig, kp.public_key))
            throw std::runtime_error(
                "Identity: self-test klucza " + path.string() +
                " nie powiodl sie — klucz uszkodzony, wymagana interwencja uzytkownika");
    } else {
        kp = signer.generate_keypair();
        save_keypair(path, kp);
    }

    std::lock_guard lk(g_cache_mtx);
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
