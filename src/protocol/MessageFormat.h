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
    SYSTEM_CMD
};

struct SecureMessage {
    MsgType     type;
    std::string sender;
    Bytes       nonce;      // 12 bajtów IV z AES-GCM
    Bytes       payload;    // zaszyfrowany tekst/dane
    int64_t     timestamp;

    // Konwersja na JSON i z powrotem
    Bytes serialize() const;
    static SecureMessage deserialize(const Bytes& data);
};

#endif