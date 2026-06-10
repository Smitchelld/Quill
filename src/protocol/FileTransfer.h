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
static constexpr size_t FILE_CHUNK_SIZE = 64 * 1024; // 64 KB

// ── FileSender ────────────────────────────────────────────────────
// Rozbija plik na zaszyfrowane chunki i wywołuje callback dla każdego
// pakietu gotowego do wysłania (jako JSON string).
//
// Użycie:
//   FileSender::send(path, aes_key, sender_name,
//       [](const std::string& pkt){ sock.send(pkt); });
//
class FileSender {
public:
    // Callback wywoływany dla każdego pakietu JSON gotowego do wysłania.
    // Zwraca false jeśli wysyłka ma być przerwana.
    using SendCallback = std::function<bool(const std::string& packet_json)>;

    // Wysyła plik. Rzuca std::runtime_error przy błędach I/O lub krypto.
    // Zwraca false jeśli callback przerwał transfer.
    static bool send(const std::filesystem::path& file_path,
                     const Bytes& aes_key,
                     const std::string& sender_name,
                     const SendCallback& on_packet);

    // Oblicza SHA-3-256 dla surowych danych
    static Bytes sha3_256(const Bytes& data);

    // AAD wiąże chunk z transfer_id i indeksem: "FILE|<tid>|<index>".
    // Podmiana metadanych w JSON psuje tag GCM.
    static Bytes chunk_aad(const std::string& transfer_id, uint32_t chunk_index);
};

// ── IncomingFile ──────────────────────────────────────────────────
// Stan częściowo odebranego pliku (przechowywany po stronie odbiorcy)
struct IncomingFile {
    std::string          file_name;
    uint64_t             file_size     = 0;
    uint32_t             total_chunks  = 0;
    uint32_t             received      = 0;        // ile chunków już odebrano
    std::map<uint32_t, Bytes> chunks;              // chunk_index → plaintext
    Bytes                expected_hash;            // SHA-3-256 z FILE_END

    // Złożenie wszystkich chunków w kolejności
    Bytes assemble() const;

    bool complete() const { return received == total_chunks; }
};

// ── FileReceiver ──────────────────────────────────────────────────
// Zarządza równoczesnymi transferami przychodzącymi (wiele plików naraz).
//
// Użycie (w dispatch loop):
//   static FileReceiver receiver;
//   if (type == "FILE_START")  receiver.on_start(j);
//   if (type == "FILE_CHUNK")  receiver.on_chunk(j, aes_key);
//   if (type == "FILE_END")    receiver.on_end(j, save_dir, on_done);
//
class FileReceiver {
public:
    // Rejestruje nowy transfer. Ignoruje duplikaty (idempotentne).
    void on_start(const nlohmann::json& j);

    // Odszyfrowuje i buforuje chunk. Rzuca std::runtime_error przy błędach krypto.
    void on_chunk(const nlohmann::json& j, const Bytes& aes_key);

    // Weryfikuje SHA-3, składa plik i zapisuje na dysk.
    // on_done(file_name, save_path, ok, error_msg) — wywoływany zawsze.
    using DoneCallback = std::function<void(
        const std::string& file_name,
        const std::filesystem::path& save_path,
        bool ok,
        const std::string& error_msg)>;

    void on_end(const nlohmann::json& j,
                const std::filesystem::path& save_dir,
                const DoneCallback& on_done);

    // Postęp transferu: zwraca {received_chunks, total_chunks} lub {0,0} jeśli brak
    std::pair<uint32_t, uint32_t> progress(const std::string& transfer_id) const;

    // Lista aktywnych transferów
    std::vector<std::string> active_transfers() const;

private:
    std::map<std::string, IncomingFile> m_incoming;
};

#endif // QUILL_FILETRANSFER_H