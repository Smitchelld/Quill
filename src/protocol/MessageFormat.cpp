#include "MessageFormat.h"
#include <chrono>

// JSON byte arrays: nlohmann::binary does not survive dump()/parse() on wire JSON.
Bytes SecureMessage::serialize() const {
    json j;
    j["t"] = static_cast<int>(type);
    j["s"] = sender;
    j["n"] = nonce;
    j["p"] = payload;
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
    msg.nonce     = j["n"].get<Bytes>();
    msg.payload   = j["p"].get<Bytes>();
    msg.timestamp = j["ts"].get<int64_t>();

    return msg;
}
