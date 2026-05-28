#include "FileTransfer.h"
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <random>
#include <iomanip>

using json = nlohmann::json;

// ── HELPERS ───────────────────────────────────────────────────────

// Generuje losowy transfer_id (8 hex znaków)
static std::string generate_transfer_id() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dist;
    std::ostringstream oss;
    oss << std::hex << std::setw(8) << std::setfill('0') << dist(gen);
    return oss.str();
}

// ── SHA-3-256 ─────────────────────────────────────────────────────

Bytes FileSender::sha3_256(const Bytes& data) {
    const EVP_MD* md = EVP_sha3_256();
    if (!md) throw std::runtime_error("SHA3-256 niedostępny w OpenSSL");

    unsigned char digest[32];
    unsigned int digest_len = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    if (!ctx ||
        EVP_DigestInit_ex(ctx, md, nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data.data(), data.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1)
    {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("SHA3-256: błąd obliczenia skrótu");
    }
    EVP_MD_CTX_free(ctx);
    return Bytes(digest, digest + digest_len);
}

// ── FileSender::send ──────────────────────────────────────────────

bool FileSender::send(const std::filesystem::path& file_path,
                      const Bytes& aes_key,
                      const std::string& sender_name,
                      const SendCallback& on_packet)
{
    // --- Wczytaj cały plik ---
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open())
        throw std::runtime_error("Nie można otworzyć pliku: " + file_path.string());

    Bytes file_data((std::istreambuf_iterator<char>(file)),
                     std::istreambuf_iterator<char>());
    file.close();

    if (file_data.empty())
        throw std::runtime_error("Plik jest pusty");

    // --- Metadane ---
    const std::string file_name   = file_path.filename().string();
    const uint64_t    file_size   = file_data.size();
    const uint32_t    total_chunks =
        static_cast<uint32_t>((file_size + FILE_CHUNK_SIZE - 1) / FILE_CHUNK_SIZE);
    const std::string transfer_id = generate_transfer_id();

    // --- SHA-3-256 całości (przed szyfrowaniem — integrity po deszyfracji) ---
    Bytes file_hash = sha3_256(file_data);

    // --- FILE_START ---
    {
        json j;
        j["type"]         = "FILE_START";
        j["transfer_id"]  = transfer_id;
        j["file_name"]    = file_name;
        j["file_size"]    = file_size;
        j["total_chunks"] = total_chunks;
        j["sender"]       = sender_name;
        if (!on_packet(j.dump())) return false;
    }

    // --- FILE_CHUNK x N ---
    for (uint32_t i = 0; i < total_chunks; ++i) {
        size_t offset = static_cast<size_t>(i) * FILE_CHUNK_SIZE;
        size_t end    = std::min(offset + FILE_CHUNK_SIZE, static_cast<size_t>(file_size));
        Bytes  chunk_plain(file_data.begin() + offset, file_data.begin() + end);

        // Każdy chunk ma własny losowy nonce — nigdy nie reużywamy
        auto enc = AesGcm::encrypt(aes_key, chunk_plain);

        json j;
        j["type"]        = "FILE_CHUNK";
        j["transfer_id"] = transfer_id;
        j["chunk_index"] = i;
        j["nonce"]       = enc.nonce;       // nlohmann/json serializuje vector<uint8_t> jako array
        j["payload"]     = enc.ciphertext;
        if (!on_packet(j.dump())) return false;
    }

    // --- FILE_END ---
    {
        json j;
        j["type"]        = "FILE_END";
        j["transfer_id"] = transfer_id;
        j["file_hash"]   = file_hash;       // SHA-3-256 plaintextu całości
        if (!on_packet(j.dump())) return false;
    }

    return true;
}

// ── IncomingFile::assemble ────────────────────────────────────────

Bytes IncomingFile::assemble() const {
    Bytes result;
    result.reserve(file_size);
    for (uint32_t i = 0; i < total_chunks; ++i) {
        auto it = chunks.find(i);
        if (it == chunks.end())
            throw std::runtime_error("Brak chunku #" + std::to_string(i));
        result.insert(result.end(), it->second.begin(), it->second.end());
    }
    return result;
}

// ── FileReceiver ──────────────────────────────────────────────────

void FileReceiver::on_start(const json& j) {
    std::string tid = j["transfer_id"];
    if (m_incoming.count(tid)) return; // już zarejestrowany

    IncomingFile f;
    f.file_name    = j["file_name"].get<std::string>();
    f.file_size    = j["file_size"].get<uint64_t>();
    f.total_chunks = j["total_chunks"].get<uint32_t>();
    m_incoming[tid] = std::move(f);
}

void FileReceiver::on_chunk(const json& j, const Bytes& aes_key) {
    std::string tid = j["transfer_id"];
    auto it = m_incoming.find(tid);
    if (it == m_incoming.end()) return; // FILE_START jeszcze nie dotarł, zignoruj

    uint32_t idx  = j["chunk_index"].get<uint32_t>();
    Bytes nonce   = j["nonce"].get<Bytes>();
    Bytes payload = j["payload"].get<Bytes>();

    // Rzuca std::runtime_error przy błędzie integralności GCM TAG
    Bytes plain = AesGcm::decrypt_bytes(aes_key, nonce, payload);

    if (it->second.chunks.count(idx) == 0) {
        it->second.chunks[idx] = std::move(plain);
        it->second.received++;
    }
}

void FileReceiver::on_end(const json& j,
                           const std::filesystem::path& save_dir,
                           const DoneCallback& on_done)
{
    std::string tid = j["transfer_id"];
    auto it = m_incoming.find(tid);
    if (it == m_incoming.end()) {
        on_done("?", {}, false, "Nieznany transfer_id: " + tid);
        return;
    }

    IncomingFile& f = it->second;

    if (!f.complete()) {
        on_done(f.file_name, {}, false,
            "Transfer niekompletny: odebrano " + std::to_string(f.received) +
            "/" + std::to_string(f.total_chunks) + " chunków");
        m_incoming.erase(it);
        return;
    }

    // --- Złóż plik ---
    Bytes data;
    try {
        data = f.assemble();
    } catch (const std::exception& e) {
        on_done(f.file_name, {}, false, std::string("Błąd składania: ") + e.what());
        m_incoming.erase(it);
        return;
    }

    // --- Weryfikacja SHA-3-256 ---
    Bytes received_hash = j["file_hash"].get<Bytes>();
    Bytes computed_hash = FileSender::sha3_256(data);

    if (received_hash != computed_hash) {
        on_done(f.file_name, {}, false, "INTEGRITY FAILURE: SHA-3 hash nie pasuje!");
        m_incoming.erase(it);
        return;
    }

    // --- Zapisz na dysk ---
    std::error_code ec;
    std::filesystem::create_directories(save_dir, ec);
    if (ec && ec.value() != 0) {
        on_done(f.file_name, {}, false, "Błąd systemu plików: " + ec.message());
        m_incoming.erase(it);
        return;
    }
    std::filesystem::path save_path = save_dir / f.file_name;

    // Unikaj nadpisywania — dodaj sufiks jeśli plik istnieje
    if (std::filesystem::exists(save_path)) {
        auto stem = save_path.stem().string();
        auto ext  = save_path.extension().string();
        int  n    = 1;
        do {
            save_path = save_dir / (stem + "_" + std::to_string(n++) + ext);
        } while (std::filesystem::exists(save_path));
    }

    std::ofstream out(save_path, std::ios::binary);
    if (!out.is_open()) {
        on_done(f.file_name, {}, false, "Nie można zapisać: " + save_path.string());
        m_incoming.erase(it);
        return;
    }
    out.write(reinterpret_cast<const char*>(data.data()), data.size());
    out.close();

    std::string name_copy = f.file_name;
    m_incoming.erase(it);
    on_done(name_copy, save_path, true, "");
}

std::pair<uint32_t, uint32_t> FileReceiver::progress(const std::string& transfer_id) const {
    auto it = m_incoming.find(transfer_id);
    if (it == m_incoming.end()) return {0, 0};
    return {it->second.received, it->second.total_chunks};
}

std::vector<std::string> FileReceiver::active_transfers() const {
    std::vector<std::string> ids;
    for (auto& [id, _] : m_incoming) ids.push_back(id);
    return ids;
}