#ifndef QUILL_MESSAGEFORMAT_H
#define QUILL_MESSAGEFORMAT_H

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <cstdint>

using Bytes = std::vector<uint8_t>;
using json = nlohmann::json;

enum class MsgType {
    CHAT,
    FILE_CHUNK,
    HANDSHAKE,
    SYSTEM_CMD,
    FILE_START,
    FILE_END
};

struct SecureMessage {
    MsgType     type;
    std::string sender;
    Bytes       nonce;      // 12 bajtów IV z AES-GCM
    Bytes       payload;    // zaszyfrowany tekst/dane
    int64_t     timestamp;

    std::string  file_name;       // FILE_START
    uint64_t     file_size = 0;   // FILE_START
    uint32_t     chunk_index = 0; // FILE_CHUNK
    uint32_t     total_chunks = 0;// FILE_START
    std::string  transfer_id;     // wszystkie typy FILE_*
    Bytes        file_hash;       // FILE_END (SHA-3-256)

    // Konwersja na JSON i z powrotem
    Bytes serialize() const;
    static SecureMessage deserialize(const Bytes& data);
};

#endif