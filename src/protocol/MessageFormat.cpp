#include "MessageFormat.h"
#include <chrono>

// Helpery do kodowania Base64 (JSON nie lubi surowych bajtów)
// Wykorzystamy wbudowane w nlohmann/json funkcje binarne
Bytes SecureMessage::serialize() const {
    json j;
    j["t"] = static_cast<int>(type);
    j["s"] = sender;
    j["n"] = json::binary(nonce);
    j["p"] = json::binary(payload);
    j["ts"] = timestamp;

    std::string s = j.dump();
    return Bytes(s.begin(), s.end());
}

SecureMessage SecureMessage::deserialize(const Bytes& data) {
    std::string s(data.begin(), data.end());
    auto j = json::parse(s);

    SecureMessage msg;
    msg.type      = static_cast<MsgType>(j["t"].get<int>());
    msg.sender    = j["s"].get<std::string>();
    msg.nonce     = j["n"].get<json::binary_t>();
    msg.payload   = j["p"].get<json::binary_t>();
    msg.timestamp = j["ts"].get<int64_t>();

    return msg;
}