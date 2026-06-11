#include "FileTransfer.h"
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <random>
#include <iomanip>
#include <algorithm>

using json = nlohmann::json;

// ── HELPERS ───────────────────────────────────────────────────────

static std::string generate_transfer_id() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dist;
    std::ostringstream oss;
    oss << std::hex << std::setw(8) << std::setfill('0') << dist(gen);
    return oss.str();
}

// ── AAD / SHA-3 ───────────────────────────────────────────────────

Bytes FileSender::chunk_aad(const std::string& transfer_id, uint32_t chunk_index) {
    std::string s = "FILE|" + transfer_id + "|" + std::to_string(chunk_index);
    return Bytes(s.begin(), s.end());
}

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

// ── FileSenderSession ─────────────────────────────────────────────

FileSenderSession FileSenderSession::open(const std::filesystem::path& file_path,
                                          const Bytes& aes_key,
                                          const std::string& sender_name)
{
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open())
        throw std::runtime_error("Nie można otworzyć pliku: " + file_path.string());

    Bytes file_data((std::istreambuf_iterator<char>(file)),
                     std::istreambuf_iterator<char>());
    file.close();

    if (file_data.empty())
        throw std::runtime_error("Plik jest pusty");

    FileSenderSession session;
    session.m_transfer_id  = generate_transfer_id();
    session.m_aes_key      = aes_key;
    session.m_sender_name  = sender_name;
    session.m_file_name    = file_path.filename().string();
    session.m_file_size    = file_data.size();
    session.m_total_chunks = static_cast<uint32_t>(
        (session.m_file_size + FILE_CHUNK_SIZE - 1) / FILE_CHUNK_SIZE);
    session.m_file_hash    = FileSender::sha3_256(file_data);

    session.m_chunks.resize(session.m_total_chunks);
    for (uint32_t i = 0; i < session.m_total_chunks; ++i) {
        size_t offset = static_cast<size_t>(i) * FILE_CHUNK_SIZE;
        size_t end    = std::min(offset + FILE_CHUNK_SIZE, file_data.size());
        session.m_chunks[i] = Bytes(file_data.begin() + offset, file_data.begin() + end);
    }
    return session;
}

bool FileSenderSession::send_start(const FileSender::SendCallback& on_packet) const {
    json j;
    j["type"]         = "FILE_START";
    j["transfer_id"]  = m_transfer_id;
    j["file_name"]    = m_file_name;
    j["file_size"]    = m_file_size;
    j["total_chunks"] = m_total_chunks;
    j["sender"]       = m_sender_name;
    return on_packet(j.dump());
}

bool FileSenderSession::send_chunk_packet(uint32_t index,
                                          const FileSender::SendCallback& on_packet) const
{
    if (index >= m_total_chunks)
        throw std::runtime_error("Nieprawidłowy chunk_index: " + std::to_string(index));

    const Bytes& plain = m_chunks[index];
    auto enc = AesGcm::encrypt(m_aes_key, plain,
                               FileSender::chunk_aad(m_transfer_id, index));

    json j;
    j["type"]        = "FILE_CHUNK";
    j["transfer_id"] = m_transfer_id;
    j["chunk_index"] = index;
    j["chunk_hash"]  = FileSender::sha3_256(plain); // SHA-3 plaintextu — weryfikacja przed buforowaniem
    j["nonce"]       = enc.nonce;
    j["payload"]     = enc.ciphertext;
    return on_packet(j.dump());
}

bool FileSenderSession::send_chunk(uint32_t index,
                                   const FileSender::SendCallback& on_packet) const
{
    return send_chunk_packet(index, on_packet);
}

bool FileSenderSession::send_all_chunks(const FileSender::SendCallback& on_packet) const {
    for (uint32_t i = 0; i < m_total_chunks; ++i)
        if (!send_chunk_packet(i, on_packet)) return false;
    return true;
}

bool FileSenderSession::send_end(const FileSender::SendCallback& on_packet) const {
    json j;
    j["type"]        = "FILE_END";
    j["transfer_id"] = m_transfer_id;
    j["file_hash"]   = m_file_hash;
    return on_packet(j.dump());
}

bool FileSenderSession::send_all(const FileSender::SendCallback& on_packet) {
    return send_start(on_packet) && send_all_chunks(on_packet) && send_end(on_packet);
}

bool FileSenderSession::retransmit(const std::vector<uint32_t>& indices,
                                     const FileSender::SendCallback& on_packet) const
{
    for (uint32_t idx : indices)
        if (!send_chunk_packet(idx, on_packet)) return false;
    return true;
}

// ── FileSender::send (kompatybilność wsteczna) ────────────────────

bool FileSender::send(const std::filesystem::path& file_path,
                      const Bytes& aes_key,
                      const std::string& sender_name,
                      const SendCallback& on_packet)
{
    auto session = FileSenderSession::open(file_path, aes_key, sender_name);
    return session.send_all(on_packet);
}

// ── IncomingFile ──────────────────────────────────────────────────

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
    if (m_incoming.count(tid)) return;

    IncomingFile f;
    f.file_name    = j["file_name"].get<std::string>();
    f.file_size    = j["file_size"].get<uint64_t>();
    f.total_chunks = j["total_chunks"].get<uint32_t>();
    m_incoming[tid] = std::move(f);
}

void FileReceiver::on_chunk(const json& j, const Bytes& aes_key) {
    std::string tid = j["transfer_id"];
    auto it = m_incoming.find(tid);
    if (it == m_incoming.end()) return;

    uint32_t idx  = j["chunk_index"].get<uint32_t>();
    Bytes nonce   = j["nonce"].get<Bytes>();
    Bytes payload = j["payload"].get<Bytes>();

    Bytes plain = AesGcm::decrypt_bytes(aes_key, nonce, payload,
                                        FileSender::chunk_aad(tid, idx));

    if (!j.contains("chunk_hash"))
        throw std::runtime_error("FILE_CHUNK: brak chunk_hash");

    Bytes expected_hash = j["chunk_hash"].get<Bytes>();
    if (expected_hash.size() != 32)
        throw std::runtime_error("FILE_CHUNK: nieprawidlowy rozmiar chunk_hash");

    Bytes actual_hash = FileSender::sha3_256(plain);
    if (actual_hash != expected_hash)
        throw std::runtime_error("FILE_CHUNK: chunk_hash nie pasuje (chunk #" +
                                 std::to_string(idx) + ")");

    if (it->second.chunks.count(idx) == 0) {
        it->second.chunks[idx] = std::move(plain);
        it->second.received++;
    }
}

std::vector<uint32_t> FileReceiver::missing_chunks(const std::string& transfer_id) const {
    auto it = m_incoming.find(transfer_id);
    if (it == m_incoming.end()) return {};

    std::vector<uint32_t> missing;
    missing.reserve(it->second.total_chunks);
    for (uint32_t i = 0; i < it->second.total_chunks; ++i)
        if (it->second.chunks.count(i) == 0) missing.push_back(i);
    return missing;
}

json FileReceiver::make_nack(const std::string& transfer_id) const {
    json j;
    j["type"]        = "FILE_NACK";
    j["transfer_id"] = transfer_id;
    j["missing"]     = missing_chunks(transfer_id);
    return j;
}

bool FileReceiver::needs_nack(const std::string& transfer_id) const {
    auto it = m_incoming.find(transfer_id);
    return it != m_incoming.end() && it->second.awaiting_end && !it->second.complete();
}

bool FileReceiver::finalize_transfer(const std::string& transfer_id,
                                     const std::filesystem::path& save_dir,
                                     const DoneCallback& on_done)
{
    auto it = m_incoming.find(transfer_id);
    if (it == m_incoming.end()) {
        on_done("?", {}, false, "Nieznany transfer_id: " + transfer_id);
        return false;
    }

    IncomingFile& f = it->second;

    if (!f.complete()) {
        on_done(f.file_name, {}, false,
            "Transfer niekompletny: odebrano " + std::to_string(f.received) +
            "/" + std::to_string(f.total_chunks) + " chunków");
        m_incoming.erase(it);
        return false;
    }

    Bytes data;
    try {
        data = f.assemble();
    } catch (const std::exception& e) {
        on_done(f.file_name, {}, false, std::string("Błąd składania: ") + e.what());
        m_incoming.erase(it);
        return false;
    }

    Bytes computed_hash = FileSender::sha3_256(data);
    if (f.expected_hash != computed_hash) {
        on_done(f.file_name, {}, false, "INTEGRITY FAILURE: SHA-3 hash nie pasuje!");
        m_incoming.erase(it);
        return false;
    }

    std::error_code ec;
    std::filesystem::create_directories(save_dir, ec);
    if (ec && ec.value() != 0) {
        on_done(f.file_name, {}, false, "Błąd systemu plików: " + ec.message());
        m_incoming.erase(it);
        return false;
    }
    std::filesystem::path save_path = save_dir / f.file_name;

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
        return false;
    }
    out.write(reinterpret_cast<const char*>(data.data()), data.size());
    out.close();

    std::string name_copy = f.file_name;
    m_incoming.erase(it);
    on_done(name_copy, save_path, true, "");
    return true;
}

FileEndStatus FileReceiver::on_end(const json& j,
                                   const std::filesystem::path& save_dir,
                                   const DoneCallback& on_done)
{
    std::string tid = j["transfer_id"];
    auto it = m_incoming.find(tid);
    if (it == m_incoming.end()) {
        on_done("?", {}, false, "Nieznany transfer_id: " + tid);
        return FileEndStatus::Failed;
    }

    IncomingFile& f = it->second;
    f.expected_hash = j["file_hash"].get<Bytes>();

    if (!f.complete()) {
        f.awaiting_end = true;
        f.nack_rounds++;
        if (f.nack_rounds > FILE_MAX_NACK_ROUNDS) {
            on_done(f.file_name, {}, false,
                "Transfer niekompletny po " + std::to_string(FILE_MAX_NACK_ROUNDS) +
                " próbach retransmisji");
            m_incoming.erase(it);
            return FileEndStatus::Failed;
        }
        return FileEndStatus::NeedsNack;
    }

    finalize_transfer(tid, save_dir, on_done);
    return FileEndStatus::Complete;
}

bool FileReceiver::try_finalize(const std::string& transfer_id,
                                  const std::filesystem::path& save_dir,
                                  const DoneCallback& on_done)
{
    auto it = m_incoming.find(transfer_id);
    if (it == m_incoming.end() || !it->second.awaiting_end || !it->second.complete())
        return false;
    return finalize_transfer(transfer_id, save_dir, on_done);
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
