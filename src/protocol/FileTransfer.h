#ifndef QUILL_FILETRANSFER_H
#define QUILL_FILETRANSFER_H

#include "../crypto/AesGcm.h"
#include <string>
#include <vector>
#include <map>
#include <functional>
#include <cstdint>
#include <filesystem>
#include <nlohmann/json_fwd.hpp>

using Bytes = std::vector<uint8_t>;

// ── STAŁE ─────────────────────────────────────────────────────────
static constexpr size_t  FILE_CHUNK_SIZE      = 64 * 1024; // 64 KB
static constexpr uint32_t FILE_MAX_NACK_ROUNDS = 5;

// ── FileSender ────────────────────────────────────────────────────
class FileSender {
public:
    using SendCallback = std::function<bool(const std::string& packet_json)>;

    static bool send(const std::filesystem::path& file_path,
                     const Bytes& aes_key,
                     const std::string& sender_name,
                     const SendCallback& on_packet);

    static Bytes sha3_256(const Bytes& data);

    // AAD wiąże chunk z transfer_id i indeksem: "FILE|<tid>|<index>".
    static Bytes chunk_aad(const std::string& transfer_id, uint32_t chunk_index);

    // SHA-3-256 pojedynczego chunka plaintextu (pole chunk_hash w FILE_CHUNK).
};

// Sesja nadawcy — trzyma plaintext chunków do selective repeat (nowy nonce przy retransmisji).
class FileSenderSession {
public:
    static FileSenderSession open(const std::filesystem::path& file_path,
                                  const Bytes& aes_key,
                                  const std::string& sender_name);

    const std::string& transfer_id() const { return m_transfer_id; }
    uint32_t total_chunks() const { return m_total_chunks; }

    bool send_start(const FileSender::SendCallback& on_packet) const;
    bool send_chunk(uint32_t index, const FileSender::SendCallback& on_packet) const;
    bool send_all_chunks(const FileSender::SendCallback& on_packet) const;
    bool send_end(const FileSender::SendCallback& on_packet) const;
    bool send_all(const FileSender::SendCallback& on_packet);

    bool retransmit(const std::vector<uint32_t>& indices,
                    const FileSender::SendCallback& on_packet) const;

private:
    bool send_chunk_packet(uint32_t index, const FileSender::SendCallback& on_packet) const;

    std::string              m_transfer_id;
    Bytes                    m_aes_key;
    std::string              m_sender_name;
    std::string              m_file_name;
    uint64_t                 m_file_size = 0;
    uint32_t                 m_total_chunks = 0;
    Bytes                    m_file_hash;
    std::vector<Bytes>       m_chunks;
};

// ── IncomingFile ──────────────────────────────────────────────────
struct IncomingFile {
    std::string               file_name;
    uint64_t                  file_size     = 0;
    uint32_t                  total_chunks  = 0;
    uint32_t                  received      = 0;
    std::map<uint32_t, Bytes> chunks;
    Bytes                     expected_hash;
    bool                      awaiting_end  = false; // FILE_END dotarł, brakuje chunków
    uint32_t                  nack_rounds   = 0;

    Bytes assemble() const;
    bool complete() const { return received == total_chunks; }
};

enum class FileEndStatus {
    Complete,   // plik zapisany, on_done(ok=true)
    NeedsNack,  // brakuje chunków — wyślij FILE_NACK, stan transferu zachowany
    Failed      // błąd końcowy, on_done(ok=false)
};

// ── FileReceiver ──────────────────────────────────────────────────
class FileReceiver {
public:
    using DoneCallback = std::function<void(
        const std::string& file_name,
        const std::filesystem::path& save_path,
        bool ok,
        const std::string& error_msg)>;

    void on_start(const nlohmann::json& j);
    void on_chunk(const nlohmann::json& j, const Bytes& aes_key);

    // Complete / Failed wywołują on_done. NeedsNack — nie; wyślij make_nack().
    FileEndStatus on_end(const nlohmann::json& j,
                         const std::filesystem::path& save_dir,
                         const DoneCallback& on_done);

    // Po uzupełnieniu brakujących chunków (FILE_END już był).
    bool try_finalize(const std::string& transfer_id,
                      const std::filesystem::path& save_dir,
                      const DoneCallback& on_done);

    std::vector<uint32_t> missing_chunks(const std::string& transfer_id) const;
    nlohmann::json make_nack(const std::string& transfer_id) const;
    bool needs_nack(const std::string& transfer_id) const;

    std::pair<uint32_t, uint32_t> progress(const std::string& transfer_id) const;
    std::vector<std::string> active_transfers() const;

private:
    bool finalize_transfer(const std::string& transfer_id,
                           const std::filesystem::path& save_dir,
                           const DoneCallback& on_done);

    std::map<std::string, IncomingFile> m_incoming;
};

#endif // QUILL_FILETRANSFER_H
