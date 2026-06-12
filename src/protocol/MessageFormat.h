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
    FILE_END,
    FILE_NACK
};

struct SecureMessage {
    MsgType     type;
    std::string sender;
    Bytes       nonce;
    Bytes       payload;
    int64_t     timestamp;

    std::string  file_name;
    uint64_t     file_size = 0;
    uint32_t     chunk_index = 0;
    uint32_t     total_chunks = 0;
    std::string  transfer_id;
    Bytes        file_hash;

    Bytes serialize() const;
    static SecureMessage deserialize(const Bytes& data);
};

#endif
